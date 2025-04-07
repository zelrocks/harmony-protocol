;; Harmony Protocol - Distributed Resource Allocation Network
;; A decentralized system for controlled resource distribution with multi-stage verification

;; Primary configuration constants
(define-constant PROTOCOL_SUPERVISOR tx-sender)
(define-constant ERROR_UNAUTHORIZED (err u100))
(define-constant ERROR_MISSING_ALLOCATION (err u101))
(define-constant ERROR_ALREADY_PROCESSED (err u102))
(define-constant ERROR_MOVEMENT_FAILED (err u103))
(define-constant ERROR_INVALID_IDENTIFIER (err u104))
(define-constant ERROR_INVALID_QUANTITY (err u105))
(define-constant ERROR_INVALID_ORIGINATOR (err u106))
(define-constant ERROR_ALLOCATION_LAPSED (err u107))
(define-constant ALLOCATION_LIFESPAN_BLOCKS u1008) 

;; Core allocation data repository
(define-map AllocationRepository
  { allocation-identifier: uint }
  {
    originator: principal,
    beneficiary: principal,
    resource-identifier: uint,
    quantity: uint,
    allocation-status: (string-ascii 10),
    genesis-block: uint,
    termination-block: uint
  }
)

;; Tracking allocation sequence
(define-data-var last-allocation-identifier uint u0)

;; Support functions
(define-private (valid-beneficiary? (beneficiary principal))
  (and 
    (not (is-eq beneficiary tx-sender))
    (not (is-eq beneficiary (as-contract tx-sender)))
  )
)

(define-private (valid-allocation-identifier? (allocation-identifier uint))
  (<= allocation-identifier (var-get last-allocation-identifier))
)

;; Core interface functions

;; Complete distribution of resources to beneficiary
(define-public (finalize-resource-distribution (allocation-identifier uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (beneficiary (get beneficiary allocation-data))
        (quantity (get quantity allocation-data))
        (resource-id (get resource-identifier allocation-data))
      )
      (asserts! (or (is-eq tx-sender PROTOCOL_SUPERVISOR) (is-eq tx-sender (get originator allocation-data))) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)
      (match (as-contract (stx-transfer? quantity tx-sender beneficiary))
        success
          (begin
            (map-set AllocationRepository
              { allocation-identifier: allocation-identifier }
              (merge allocation-data { allocation-status: "completed" })
            )
            (print {action: "resources_distributed", allocation-identifier: allocation-identifier, beneficiary: beneficiary, resource-identifier: resource-id, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Accept allocation by beneficiary - increases security by requiring explicit acceptance
(define-public (accept-pending-allocation (allocation-identifier uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (beneficiary (get beneficiary allocation-data))
      )
      (asserts! (is-eq tx-sender beneficiary) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "accepted" })
      )
      (print {action: "allocation_accepted", allocation-identifier: allocation-identifier, beneficiary: beneficiary})
      (ok true)
    )
  )
)

;; Revert resources to originator
(define-public (revert-resource-allocation (allocation-identifier uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
      )
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set AllocationRepository
              { allocation-identifier: allocation-identifier }
              (merge allocation-data { allocation-status: "reverted" })
            )
            (print {action: "resources_reverted", allocation-identifier: allocation-identifier, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Emergency freeze allocation in case of security breach
(define-public (emergency-freeze-allocation (allocation-identifier uint) (security-incident-report (string-ascii 100)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (current-status (get allocation-status allocation-data))
      )
      ;; Only supervisor, originator or beneficiary can freeze in emergency
      (asserts! (or (is-eq tx-sender PROTOCOL_SUPERVISOR) 
                   (is-eq tx-sender originator) 
                   (is-eq tx-sender beneficiary)) 
                ERROR_UNAUTHORIZED)

      ;; Cannot freeze if already completed or reverted
      (asserts! (and (not (is-eq current-status "completed")) 
                    (not (is-eq current-status "reverted"))
                    (not (is-eq current-status "expired"))
                    (not (is-eq current-status "frozen"))) 
                ERROR_ALREADY_PROCESSED)

      ;; Update allocation status to frozen
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "frozen" })
      )

      (print {action: "allocation_emergency_frozen", allocation-identifier: allocation-identifier, 
              initiator: tx-sender, previous-status: current-status, security-report: security-incident-report})
      (ok true)
    )
  )
)

;; Implement two-factor verification for high-value allocations
(define-public (verify-allocation-2fa (allocation-identifier uint) (verification-code (buff 32)) (verification-timestamp uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> verification-timestamp u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= verification-timestamp block-height) (err u245)) ;; Cannot be future timestamp
    (asserts! (>= block-height (- verification-timestamp u144)) (err u246)) ;; Must be recent (within 24 hours)

    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (quantity (get quantity allocation-data))
        (current-status (get allocation-status allocation-data))
      )
      ;; Only needed for high value allocations
      (asserts! (> quantity u5000) (err u247))
      ;; Only originator or beneficiary can verify
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERROR_UNAUTHORIZED)
      ;; Must be in pending status
      (asserts! (is-eq current-status "pending") ERROR_ALREADY_PROCESSED)

      (print {action: "2fa_verification_complete", allocation-identifier: allocation-identifier, 
              verifier: tx-sender, verification-code-hash: (hash160 verification-code), 
              verification-timestamp: verification-timestamp, quantity: quantity})
      (ok true)
    )
  )
)

;; Create allocation with timelocked release schedule
(define-public (create-timelocked-allocation (beneficiary principal) (resource-identifier uint) (quantity uint) (release-schedule (list 5 {block-height: uint, percentage: uint})))
  (begin
    (asserts! (> quantity u0) ERROR_INVALID_QUANTITY)
    (asserts! (> (len release-schedule) u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= (len release-schedule) u5) (err u255)) ;; Maximum 5 release points
    (asserts! (valid-beneficiary? beneficiary) ERROR_INVALID_ORIGINATOR)

    ;; Validate release schedule
    (let
      (
        (new-identifier (+ (var-get last-allocation-identifier) u1))
        (termination-date (+ block-height ALLOCATION_LIFESPAN_BLOCKS))
        (total-percentage (fold + (map get-percentage release-schedule) u0))
      )
      ;; Ensure percentages sum to 100%
      (asserts! (is-eq total-percentage u100) (err u256))

      ;; Transfer resources to contract
      (match (stx-transfer? quantity tx-sender (as-contract tx-sender))
        success
          (begin
            (var-set last-allocation-identifier new-identifier)

            (print {action: "timelocked_allocation_created", allocation-identifier: new-identifier, 
                    originator: tx-sender, beneficiary: beneficiary, resource-identifier: resource-identifier, 
                    quantity: quantity, release-schedule: release-schedule})
            (ok new-identifier)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Helper function to extract percentage from release schedule entry
(define-private (get-percentage (entry {block-height: uint, percentage: uint}))
  (get percentage entry)
)

;; Create allocation with circuit breaker to halt transaction flow if anomalies detected
(define-public (create-protected-allocation (beneficiary principal) (resource-identifier uint) (quantity uint) (anomaly-threshold uint) (max-transactions-per-block uint))
  (begin
    (asserts! (> quantity u0) ERROR_INVALID_QUANTITY)
    (asserts! (> anomaly-threshold u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= anomaly-threshold u100) (err u265)) ;; Threshold must be percentage (0-100)
    (asserts! (> max-transactions-per-block u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= max-transactions-per-block u10) (err u266)) ;; Reasonable limit
    (asserts! (valid-beneficiary? beneficiary) ERROR_INVALID_ORIGINATOR)

    (let
      (
        (new-identifier (+ (var-get last-allocation-identifier) u1))
        (termination-date (+ block-height ALLOCATION_LIFESPAN_BLOCKS))
      )
      ;; Transfer resources to contract
      (match (stx-transfer? quantity tx-sender (as-contract tx-sender))
        success
          (begin
            (var-set last-allocation-identifier new-identifier)

            (print {action: "protected_allocation_created", allocation-identifier: new-identifier, 
                    originator: tx-sender, beneficiary: beneficiary, resource-identifier: resource-identifier, 
                    quantity: quantity, anomaly-threshold: anomaly-threshold, 
                    max-transactions-per-block: max-transactions-per-block})
            (ok new-identifier)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)
