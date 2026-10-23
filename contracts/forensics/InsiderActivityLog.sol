// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title InsiderActivityLog
 * @author H0777
 * @notice On-chain behavioral activity logger for insider threat detection
 * @dev Records every sensitive action performed by authorized personnel,
 *      enabling AI-driven behavioral analysis and anomaly detection.
 *
 * Tracked Activities:
 *   - Transaction approvals and overrides
 *   - After-hours operations
 *   - Warning bypasses (override of AML/compliance flags)
 *   - Repeated actions on same beneficiary accounts
 *   - Role and permission changes
 *
 * This data feeds into the off-chain AI engine for real-time
 * insider threat scoring and pattern recognition.
 */
contract InsiderActivityLog {

    // ============================================================
    // ENUMS & STRUCTS
    // ============================================================

    enum ActivityType {
        TRANSACTION_APPROVAL,       // Approved a pending transaction
        TRANSACTION_OVERRIDE,       // Overrode a compliance warning
        BLACKLIST_ACTION,           // Added/removed from blacklist
        KYC_ACTION,                 // Verified/revoked KYC
        ROLE_CHANGE,                // Assigned/revoked a role
        POLICY_CHANGE,              // Modified compliance parameters
        AFTER_HOURS_ACCESS,         // Activity outside business hours
        REPEATED_BENEFICIARY,       // Multiple approvals for same beneficiary
        MANUAL_CLEAR                // Manually cleared a flagged transaction
    }

    struct Activity {
        uint256 id;
        address operator;           // Who performed the action
        ActivityType activityType;
        uint256 relatedTxId;        // Related transaction ID (0 if not applicable)
        address relatedAddress;     // Related beneficiary address (zero if N/A)
        string details;             // Human-readable description
        uint256 timestamp;
        bool isAfterHours;          // Flag: was this outside 8AM-5PM?
    }

    struct OperatorProfile {
        uint256 totalActions;
        uint256 overrideCount;
        uint256 afterHoursCount;
        uint256 lastActivityTimestamp;
        uint256 flagCount;              // Number of times flagged by the system
    }

    // ============================================================
    // STATE VARIABLES
    // ============================================================

    address public governance;
    uint256 private _activityCounter;

    /// @notice Business hours configuration (UTC offsets, not Baghdad local time claims)
    uint8 public businessHourStart = 8;    // 8 AM UTC
    uint8 public businessHourEnd = 17;     // 5 PM UTC

    /// @notice Allowlist of authorized recorders (e.g. AuditEngine)
    mapping(address => bool) public isRecorder;

    /// @notice All activities by ID
    mapping(uint256 => Activity) private _activities;

    /// @notice Activities per operator (for behavioral analysis)
    mapping(address => uint256[]) private _operatorActivities;

    /// @notice Operator behavioral profiles
    mapping(address => OperatorProfile) private _profiles;

    /// @notice Track operator approvals per beneficiary (for repeat detection)
    mapping(address => mapping(address => uint256)) private _beneficiaryApprovals;

    /// @notice All activity IDs
    uint256[] private _allActivityIds;

    // ============================================================
    // EVENTS
    // ============================================================

    event GovernanceTransferred(address indexed newGovernance);
    event RecorderUpdated(address indexed recorder, bool authorized);
    event BusinessHoursUpdated(uint8 startUtc, uint8 endUtc);

    event ActivityLogged(
        uint256 indexed activityId,
        address indexed operator,
        ActivityType indexed activityType,
        uint256 relatedTxId,
        bool isAfterHours,
        uint256 timestamp
    );

    event InsiderAlert(
        address indexed operator,
        string alertType,
        string details,
        uint256 timestamp
    );

    event OperatorFlagged(
        address indexed operator,
        string flagType,
        string details,
        uint256 totalFlags,
        uint256 timestamp
    );

    // ============================================================
    // MODIFIERS
    // ============================================================

    modifier onlyGovernance() {
        require(msg.sender == governance, "InsiderActivityLog: caller is not governance");
        _;
    }

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    constructor(address _governance) {
        require(_governance != address(0), "InsiderLog: invalid governance");
        governance = _governance;
    }

    // ============================================================
    // GOVERNANCE CONFIGURATION
    // ============================================================

    /**
     * @notice Transfer governance
     */
    function setGovernance(address _newGov) external onlyGovernance {
        require(_newGov != address(0), "InsiderLog: zero address");
        governance = _newGov;
        emit GovernanceTransferred(_newGov);
    }

    /**
     * @notice Configure authorized recorder contract (governance only)
     * @dev R03: in the integrated system governance is the MultiSig coordinator,
     *      so recorder changes reach this function exclusively through a
     *      SYSTEM_CONFIG proposal (InsiderActivityLog.setRecorder(address,bool)
     *      is on the closed action table; a grant waits 86,400s, a revocation
     *      executes at delay 0 — both under two independent approvals).
     */
    function setRecorder(address _recorder, bool _authorized) external onlyGovernance {
        require(_recorder != address(0), "InsiderLog: zero address");
        isRecorder[_recorder] = _authorized;
        emit RecorderUpdated(_recorder, _authorized);
    }

    // ============================================================
    // CORE FUNCTIONS
    // ============================================================

    /**
     * @notice Log an insider activity
     * @param _operator The address performing the action
     * @param _type The type of activity
     * @param _relatedTxId Related transaction ID (0 if not applicable)
     * @param _relatedAddress Related address (zero address if N/A)
     * @param _details Human-readable description
     * @return activityId The unique activity identifier
     */
    function logActivity(
        address _operator,
        ActivityType _type,
        uint256 _relatedTxId,
        address _relatedAddress,
        string calldata _details
    ) external returns (uint256 activityId) {
        require(isRecorder[msg.sender], "InsiderActivityLog: caller is not authorized recorder");
        require(_operator != address(0), "InsiderLog: invalid operator");

        _activityCounter++;
        activityId = _activityCounter;

        bool afterHours = _isAfterHours();

        Activity memory activity = Activity({
            id: activityId,
            operator: _operator,
            activityType: _type,
            relatedTxId: _relatedTxId,
            relatedAddress: _relatedAddress,
            details: _details,
            timestamp: block.timestamp,
            isAfterHours: afterHours
        });

        _activities[activityId] = activity;
        _operatorActivities[_operator].push(activityId);
        _allActivityIds.push(activityId);

        // Update operator profile
        OperatorProfile storage profile = _profiles[_operator];
        profile.totalActions++;
        profile.lastActivityTimestamp = block.timestamp;

        // Track overrides
        if (_type == ActivityType.TRANSACTION_OVERRIDE) {
            profile.overrideCount++;

            // Alert if override count exceeds threshold
            if (profile.overrideCount > 5) {
                profile.flagCount++;
                emit OperatorFlagged(
                    _operator,
                    "EXCESSIVE_OVERRIDES",
                    "Operator has overridden warnings more than 5 times",
                    profile.flagCount,
                    block.timestamp
                );
            }
        }

        // Track after-hours activity
        if (afterHours) {
            profile.afterHoursCount++;

            emit InsiderAlert(
                _operator,
                "AFTER_HOURS_ACTIVITY",
                _details,
                block.timestamp
            );

            // Flag if repeated after-hours
            if (profile.afterHoursCount > 3) {
                profile.flagCount++;
                emit OperatorFlagged(
                    _operator,
                    "REPEATED_AFTER_HOURS",
                    "Operator frequently operates outside business hours",
                    profile.flagCount,
                    block.timestamp
                );
            }
        }

        // Track repeated beneficiary approvals
        if (_relatedAddress != address(0) &&
            (_type == ActivityType.TRANSACTION_APPROVAL ||
             _type == ActivityType.MANUAL_CLEAR)) {
            _beneficiaryApprovals[_operator][_relatedAddress]++;

            if (_beneficiaryApprovals[_operator][_relatedAddress] > 10) {
                profile.flagCount++;
                emit OperatorFlagged(
                    _operator,
                    "REPEATED_BENEFICIARY",
                    "Operator repeatedly approves same beneficiary",
                    profile.flagCount,
                    block.timestamp
                );
            }
        }

        emit ActivityLogged(
            activityId,
            _operator,
            _type,
            _relatedTxId,
            afterHours,
            block.timestamp
        );
    }

    // ============================================================
    // CONFIGURATION
    // ============================================================

    /**
     * @notice Update business hours (governance only, UTC context)
     * @param _start Start hour (0-23 UTC)
     * @param _end End hour (0-23 UTC)
     */
    function setBusinessHours(uint8 _start, uint8 _end) external onlyGovernance {
        require(_start <= 24 && _end <= 24, "InsiderLog: invalid hours");
        require(_start < _end, "InsiderLog: start must be before end");
        businessHourStart = _start;
        businessHourEnd = _end;
        emit BusinessHoursUpdated(_start, _end);
    }

    // ============================================================
    // VIEW FUNCTIONS
    // ============================================================

    /**
     * @notice Get a specific activity entry
     */
    function getActivity(uint256 _activityId) external view returns (Activity memory) {
        require(
            _activityId > 0 && _activityId <= _activityCounter,
            "InsiderLog: activity does not exist"
        );
        return _activities[_activityId];
    }

    /**
     * @notice Get all activity IDs for a specific operator
     */
    function getOperatorActivities(address _operator)
        external
        view
        returns (uint256[] memory)
    {
        return _operatorActivities[_operator];
    }

    /**
     * @notice Get the behavioral profile of an operator
     */
    function getOperatorProfile(address _operator)
        external
        view
        returns (OperatorProfile memory)
    {
        return _profiles[_operator];
    }

    /**
     * @notice Get approval count for a specific operator-beneficiary pair
     */
    function getBeneficiaryApprovalCount(address _operator, address _beneficiary)
        external
        view
        returns (uint256)
    {
        return _beneficiaryApprovals[_operator][_beneficiary];
    }

    /**
     * @notice Get total number of activities logged
     */
    function totalActivities() external view returns (uint256) {
        return _activityCounter;
    }

    /**
     * @notice Get all activity IDs
     */
    function getAllActivityIds() external view returns (uint256[] memory) {
        return _allActivityIds;
    }

    // ============================================================
    // INTERNAL HELPERS
    // ============================================================

    /**
     * @dev Check if current time is outside business hours
     * @return True if the current hour is outside the configured business window
     */
    function _isAfterHours() internal view returns (bool) {
        uint256 currentHour = (block.timestamp % 1 days) / 1 hours;
        return currentHour < businessHourStart || currentHour >= businessHourEnd;
    }
}
