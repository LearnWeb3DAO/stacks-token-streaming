;; error codes
(define-constant ERR_UNAUTHORIZED (err u0))
(define-constant ERR_INVALID_SIGNATURE (err u1))
(define-constant ERR_STREAM_STILL_ACTIVE (err u2))

;; data vars
(define-data-var latest-stream-id uint u0)
(define-data-var nonce uint u0)

;; streams mapping
(define-map streams
  uint ;; stream-id
  {
    sender: principal,
    recipient: principal,
    balance: uint,
    withdrawn-balance: uint,
    payment-per-block: uint,
    timeframe: (tuple (start-block uint) (stop-block uint))
  }
)


;; Create a new stream
(define-public (stream-to
    (recipient principal)
    (initial-balance uint)
    (timeframe (tuple (start-block uint) (stop-block uint)))
    (payment-per-block uint)
  )
  (let (
    (stream {
      sender: tx-sender,
      recipient: recipient,
      balance: initial-balance,
      withdrawn-balance: u0,
      payment-per-block: payment-per-block,
      timeframe: timeframe
    })
    (current-stream-id (var-get latest-stream-id))
  )
    (begin
      (try! (stx-transfer? initial-balance tx-sender (as-contract tx-sender)))
      (map-set streams current-stream-id stream)
      (var-set latest-stream-id (+ current-stream-id u1))
      (ok current-stream-id)
    )
  )
)


;; Increase the locked STX balance for a stream
(define-public (refuel
    (stream-id uint)
    (amount uint)
  )
  (let (
    (stream (unwrap-panic (map-get? streams stream-id)))
  )
  (begin
    (asserts! (is-eq tx-sender (get sender stream)) ERR_UNAUTHORIZED)
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (map-set streams
      stream-id
      {
        sender: (get sender stream),
        recipient: (get recipient stream),
        balance: (+ (get balance stream) amount),
        withdrawn-balance: (get withdrawn-balance stream),
        payment-per-block: (get payment-per-block stream),
        timeframe: (get timeframe stream)
      }
    )
    (ok amount)
    )
  )
)

;; Check balance for a party involved in a stream
(define-read-only (balance-of
    (stream-id uint)
    (who principal)
  )
  (let (
    (stream (unwrap-panic (map-get? streams stream-id)))
    (block-delta (calculate-block-delta (get timeframe stream)))
    (recipient-balance (* block-delta (get payment-per-block stream)))
  )
    (if (is-eq who (get recipient stream))
      (- recipient-balance (get withdrawn-balance stream))
      (if (is-eq who (get sender stream))
        (- (get balance stream) recipient-balance)
        u0
      )
    )
  )
)

;; Calculate the number of blocks a stream has been active
(define-read-only (calculate-block-delta
    (timeframe (tuple (start-block uint) (stop-block uint)))
  )
  (let (
    (start-block (get start-block timeframe))
    (stop-block (get stop-block timeframe))

    (delta 
      (if (<= block-height start-block)
        ;; then
        u0
        ;; else
        (if (< block-height stop-block)
          ;; then
          (- block-height start-block)
          ;; else
          (- stop-block start-block)
        ) 
      )
    )
  )
    delta
  )
)

;; Withdraw received tokens
(define-public (withdraw
    (stream-id uint)
  )
  (let (
    (stream (unwrap-panic (map-get? streams stream-id)))
    (balance (balance-of stream-id tx-sender))
  )
  (begin
      (asserts! (is-eq tx-sender (get recipient stream)) ERR_UNAUTHORIZED)
      (map-set streams
        stream-id
        {
          sender: (get sender stream),
          recipient: (get recipient stream),
          balance: (get balance stream),
          withdrawn-balance: (+ (get withdrawn-balance stream) balance),
          payment-per-block: (get payment-per-block stream),
          timeframe: (get timeframe stream)
        }
      )
      (try! (as-contract (stx-transfer? balance tx-sender (get recipient stream))))
      (ok balance)
    )
  )
)

;; Withdraw excess locked tokens
(define-public (refund
    (stream-id uint)
  )
  (let (
    (stream (unwrap-panic (map-get? streams stream-id)))
    (balance (balance-of stream-id (get sender stream)))
  )
  (begin
      (asserts! (is-eq tx-sender (get sender stream)) ERR_UNAUTHORIZED)
      (asserts! (< (get stop-block (get timeframe stream)) block-height) ERR_STREAM_STILL_ACTIVE)
      (map-set streams
        stream-id
        {
          sender: (get sender stream),
          recipient: (get recipient stream),
          balance: (- (get balance stream) balance),
          withdrawn-balance: (get withdrawn-balance stream),
          payment-per-block: (get payment-per-block stream),
          timeframe: (get timeframe stream)
        }
      )
      (try! (as-contract (stx-transfer? balance tx-sender (get sender stream))))
      (ok balance)
    )
  )
)

;; Get hash of stream
(define-read-only (hash-stream
    (stream-id uint)
    (new-payment-per-block uint)
    (new-timeframe (tuple (start-block uint) (stop-block uint)))
  )
  (let (
    (stream (unwrap-panic (map-get? streams stream-id)))
    (msg (concat (concat (unwrap-panic (to-consensus-buff? stream)) (unwrap-panic (to-consensus-buff? new-payment-per-block))) (unwrap-panic (to-consensus-buff? new-timeframe))))
  )
    (sha256 msg)
  )
)

;; Signature verification
(define-read-only (validate-signature (hash (buff 32)) (signature (buff 65)) (signer principal))
        (is-eq 
          (principal-of? (unwrap! (secp256k1-recover? hash signature) false)) 
          (ok signer)
        )
)

;; Update stream configuration
(define-public (update-details
    (stream-id uint)
    (payment-per-block uint)
    (timeframe (tuple (start-block uint) (stop-block uint)))
    (signer principal)
    (signature (buff 65))
  )
  (let (
    (stream (unwrap-panic (map-get? streams stream-id)))    
  )
    (begin
      (asserts! (validate-signature (hash-stream stream-id payment-per-block timeframe) signature signer) ERR_INVALID_SIGNATURE)
      (asserts!
        (or
          (and (is-eq (get sender stream) tx-sender) (is-eq (get recipient stream) signer))
          (and (is-eq (get sender stream) signer) (is-eq (get recipient stream) tx-sender))
        )
        ERR_UNAUTHORIZED
      )
      (map-set streams
        stream-id
        {
          sender: (get sender stream),
          recipient: (get recipient stream),
          balance: (get balance stream),
          withdrawn-balance: (get withdrawn-balance stream),
          payment-per-block: payment-per-block,
          timeframe: timeframe
        }
      )
      (ok true)
    )
  )
)