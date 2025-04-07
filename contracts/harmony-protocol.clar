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
