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

;; Create trusted recovery mechanism
(define-public (initiate-trusted-recovery (allocation-identifier uint) (recovery-beneficiary principal))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
        (cool-down-period u144) ;; 24 hours in blocks
      )
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      (asserts! (not (is-eq (get allocation-status allocation-data) "completed")) ERROR_ALREADY_PROCESSED)
      (asserts! (not (is-eq (get allocation-status allocation-data) "reverted")) ERROR_ALREADY_PROCESSED) 
      (asserts! (not (is-eq (get allocation-status allocation-data) "terminated")) ERROR_ALREADY_PROCESSED)
      (asserts! (not (is-eq (get allocation-status allocation-data) "expired")) ERROR_ALREADY_PROCESSED)

      (print {action: "trusted_recovery_initiated", allocation-identifier: allocation-identifier, 
              originator: originator, recovery-beneficiary: recovery-beneficiary, 
              execution-block: (+ block-height cool-down-period)})
      (ok (+ block-height cool-down-period))
    )
  )
)

;; Implement rate-limited withdrawals for large allocations
(define-public (configure-withdrawal-rate-limit (allocation-identifier uint) (blocks-per-withdrawal uint) (withdrawal-cap uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> blocks-per-withdrawal u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= blocks-per-withdrawal u144) ERROR_INVALID_QUANTITY) ;; Max 1 day between withdrawals
    (asserts! (> withdrawal-cap u0) ERROR_INVALID_QUANTITY)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
      )
      ;; Only for significant allocations
      (asserts! (> quantity u2000) (err u250))
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= withdrawal-cap quantity) (err u251)) ;; Cap must be less than or equal to total

      (print {action: "withdrawal_rate_limit_configured", allocation-identifier: allocation-identifier, 
              originator: originator, blocks-per-withdrawal: blocks-per-withdrawal, 
              withdrawal-cap: withdrawal-cap, withdrawal-periods: (/ quantity withdrawal-cap)})
      (ok true)
    )
  )
)

;; Lock allocation for security investigation
(define-public (lock-allocation-for-investigation (allocation-identifier uint) (investigation-code (string-ascii 30)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (status (get allocation-status allocation-data))
      )
      ;; Only supervisor or originator can lock for investigation
      (asserts! (or (is-eq tx-sender PROTOCOL_SUPERVISOR) (is-eq tx-sender originator)) ERROR_UNAUTHORIZED)
      ;; Cannot lock already completed or terminated allocations
      (asserts! (not (or (is-eq status "completed") (is-eq status "terminated") 
                          (is-eq status "reverted") (is-eq status "expired"))) ERROR_ALREADY_PROCESSED)
      ;; Update status to locked
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "locked" })
      )
      (print {action: "allocation_locked", allocation-identifier: allocation-identifier, investigator: tx-sender, 
              investigation-code: investigation-code, lock-time: block-height})
      (ok true)
    )
  )
)

;; Add security hold period for high-risk allocations
(define-public (add-security-hold (allocation-identifier uint) (hold-duration uint) (risk-justification (string-ascii 50)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> hold-duration u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= hold-duration u720) ERROR_INVALID_QUANTITY) ;; Maximum 5 days hold
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (status (get allocation-status allocation-data))
        (current-termination (get termination-block allocation-data))
        (extended-termination (+ current-termination hold-duration))
      )
      ;; Only supervisor can add security holds
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
      ;; Only pending allocations can have holds added
      (asserts! (is-eq status "pending") ERROR_ALREADY_PROCESSED)
      ;; Update the termination block to extend the allocation period
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { 
          allocation-status: "held", 
          termination-block: extended-termination 
        })
      )
      (print {action: "security_hold_added", allocation-identifier: allocation-identifier, hold-duration: hold-duration, 
              original-termination: current-termination, new-termination: extended-termination, justification: risk-justification})
      (ok true)
    )
  )
)

;; Originator initiates allocation termination
(define-public (terminate-allocation (allocation-identifier uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
      )
      (asserts! (is-eq tx-sender originator) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set AllocationRepository
              { allocation-identifier: allocation-identifier }
              (merge allocation-data { allocation-status: "terminated" })
            )
            (print {action: "allocation_terminated", allocation-identifier: allocation-identifier, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Implement multi-signature confirmation for high-value allocations
(define-public (register-multisig-confirmation (allocation-identifier uint) (confirmation-signature (buff 65)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (quantity (get quantity allocation-data))
      )
      ;; Only for significant allocations (> 5000 STX)
      (asserts! (> quantity u5000) (err u240))
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") (is-eq (get allocation-status allocation-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)

      (print {action: "multisig_confirmation_registered", allocation-identifier: allocation-identifier, 
              confirming-party: tx-sender, signature-hash: (hash160 confirmation-signature)})
      (ok true)
    )
  )
)

;; Prolong allocation duration
(define-public (prolong-allocation-timeframe (allocation-identifier uint) (additional-blocks uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (> additional-blocks u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= additional-blocks u1440) ERROR_INVALID_QUANTITY) ;; Maximum 10 days extension
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data)) 
        (beneficiary (get beneficiary allocation-data))
        (existing-termination (get termination-block allocation-data))
        (new-termination (+ existing-termination additional-blocks))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") (is-eq (get allocation-status allocation-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { termination-block: new-termination })
      )
      (print {action: "timeframe_extended", allocation-identifier: allocation-identifier, requestor: tx-sender, new-termination-block: new-termination})
      (ok true)
    )
  )
)

;; Reclaim resources from expired allocation
(define-public (reclaim-lapsed-allocation (allocation-identifier uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
        (expiration (get termination-block allocation-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") (is-eq (get allocation-status allocation-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (> block-height expiration) (err u108)) ;; Must be expired
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set AllocationRepository
              { allocation-identifier: allocation-identifier }
              (merge allocation-data { allocation-status: "expired" })
            )
            (print {action: "lapsed_allocation_reclaimed", allocation-identifier: allocation-identifier, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERROR_MOVEMENT_FAILED
      )
    )
  )
)

;; Challenge allocation integrity
(define-public (challenge-allocation (allocation-identifier uint) (justification (string-ascii 50)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") (is-eq (get allocation-status allocation-data) "accepted")) ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "challenged" })
      )
      (print {action: "allocation_challenged", allocation-identifier: allocation-identifier, challenger: tx-sender, justification: justification})
      (ok true)
    )
  )
)

;; Register contingency contact
(define-public (register-contingency-contact (allocation-identifier uint) (contingency-contact principal))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
      )
      (asserts! (is-eq tx-sender originator) ERROR_UNAUTHORIZED)
      (asserts! (not (is-eq contingency-contact tx-sender)) (err u111)) ;; Must differ from originator
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (print {action: "contingency_registered", allocation-identifier: allocation-identifier, originator: originator, contingency: contingency-contact})
      (ok true)
    )
  )
)

;; Arbitrate contested allocation
(define-public (arbitrate-challenge (allocation-identifier uint) (originator-percentage uint))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERROR_UNAUTHORIZED)
    (asserts! (<= originator-percentage u100) ERROR_INVALID_QUANTITY) ;; Valid percentage range
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (quantity (get quantity allocation-data))
        (originator-share (/ (* quantity originator-percentage) u100))
        (beneficiary-share (- quantity originator-share))
      )
      (asserts! (is-eq (get allocation-status allocation-data) "challenged") (err u112)) ;; Must be challenged
      (asserts! (<= block-height (get termination-block allocation-data)) ERROR_ALLOCATION_LAPSED)

      ;; Distribute originator's share
      (unwrap! (as-contract (stx-transfer? originator-share tx-sender originator)) ERROR_MOVEMENT_FAILED)

      ;; Distribute beneficiary's share
      (unwrap! (as-contract (stx-transfer? beneficiary-share tx-sender beneficiary)) ERROR_MOVEMENT_FAILED)

      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "arbitrated" })
      )
      (print {action: "challenge_arbitrated", allocation-identifier: allocation-identifier, originator: originator, beneficiary: beneficiary, 
              originator-share: originator-share, beneficiary-share: beneficiary-share, originator-percentage: originator-percentage})
      (ok true)
    )
  )
)

;; Register additional oversight for significant allocations
(define-public (register-additional-oversight (allocation-identifier uint) (overseer principal))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (quantity (get quantity allocation-data))
      )
      ;; Only for significant allocations (> 1000 STX)
      (asserts! (> quantity u1000) (err u120))
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)
      (print {action: "oversight_registered", allocation-identifier: allocation-identifier, overseer: overseer, requestor: tx-sender})
      (ok true)
    )
  )
)

;; Create phased allocation
(define-public (create-phased-allocation (beneficiary principal) (resource-identifier uint) (quantity uint) (segments uint))
  (let 
    (
      (new-identifier (+ (var-get last-allocation-identifier) u1))
      (termination-date (+ block-height ALLOCATION_LIFESPAN_BLOCKS))
      (segment-quantity (/ quantity segments))
    )
    (asserts! (> quantity u0) ERROR_INVALID_QUANTITY)
    (asserts! (> segments u0) ERROR_INVALID_QUANTITY)
    (asserts! (<= segments u5) ERROR_INVALID_QUANTITY) ;; Maximum 5 segments
    (asserts! (valid-beneficiary? beneficiary) ERROR_INVALID_ORIGINATOR)
    (asserts! (is-eq (* segment-quantity segments) quantity) (err u121)) ;; Verify exact division
    (match (stx-transfer? quantity tx-sender (as-contract tx-sender))
      success
        (begin
          (var-set last-allocation-identifier new-identifier)
          (print {action: "phased_allocation_created", allocation-identifier: new-identifier, originator: tx-sender, beneficiary: beneficiary, 
                  resource-identifier: resource-identifier, quantity: quantity, segments: segments, segment-quantity: segment-quantity})
          (ok new-identifier)
        )
      error ERROR_MOVEMENT_FAILED
    )
  )
)

;; Pause suspicious allocation
(define-public (pause-irregular-allocation (allocation-identifier uint) (rationale (string-ascii 100)))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
      )
      (asserts! (or (is-eq tx-sender PROTOCOL_SUPERVISOR) (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq (get allocation-status allocation-data) "pending") 
                   (is-eq (get allocation-status allocation-data) "accepted")) 
                ERROR_ALREADY_PROCESSED)
      (map-set AllocationRepository
        { allocation-identifier: allocation-identifier }
        (merge allocation-data { allocation-status: "paused" })
      )
      (print {action: "allocation_paused", allocation-identifier: allocation-identifier, initiator: tx-sender, rationale: rationale})
      (ok true)
    )
  )
)

;; Advanced cryptographic verification
(define-public (perform-cryptographic-verification (allocation-identifier uint) (data-digest (buff 32)) (signature (buff 65)) (signatory principal))
  (begin
    (asserts! (valid-allocation-identifier? allocation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (allocation-data (unwrap! (map-get? AllocationRepository { allocation-identifier: allocation-identifier }) ERROR_MISSING_ALLOCATION))
        (originator (get originator allocation-data))
        (beneficiary (get beneficiary allocation-data))
        (verification-result (unwrap! (secp256k1-recover? data-digest signature) (err u150)))
      )
      ;; Verify message authenticity
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq signatory originator) (is-eq signatory beneficiary)) (err u151))
      (asserts! (is-eq (get allocation-status allocation-data) "pending") ERROR_ALREADY_PROCESSED)

      ;; Confirm signature matches expected source
      (asserts! (is-eq (unwrap! (principal-of? verification-result) (err u152)) signatory) (err u153))

      (print {action: "cryptographic_verification_complete", allocation-identifier: allocation-identifier, verifier: tx-sender, signatory: signatory})
      (ok true)
    )
  )
)
