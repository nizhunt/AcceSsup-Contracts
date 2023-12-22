// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title AcceSsup: An access management protocol with royalty and renting feature
/// @author Nishant Singh
/// @notice Implements a system for access management with royalty and renting
contract AcceSsup is Ownable, ERC1155 {
    using MessageHashUtils for bytes32;
    using ECDSA for bytes32;

    // Custom Errors
    error AcceSsup_ServiceProviderMismatch();
    error AcceSsup_ContentDoesNotExist();
    error AcceSsup_ServiceProviderNotValid();
    error AcceSsup_FeeTransferFailed();
    error AcceSsup_InvalidContentId();
    error AcceSsup_PayRoyaltyFeeFailed();
    error AcceSsup_NoFeeToWithdraw();
    error AcceSsup_Unauthorized();
    error AcceSsup_InvalidSignature();

    // Events:
    event NewAccess(
        uint256 indexed contentId,
        address indexed serviceProvider,
        uint256 validity,
        uint256 fee,
        address indexed subscriber,
        uint256 royalty
    );
    event NewContent(address indexed serviceProvider, uint256 indexed contentId);
    event FeeWithdrawn(address indexed serviceProvider, address indexed owner, uint256 fee);
    event SPOwnerSet(address indexed serviceProvider, address indexed SPOwner);
    event NewBaseUri(string baseUri);
    event NewServiceProviderUri(address indexed serviceProvider, string serviceProviderUri);
    event NewContentUri(uint256 indexed contentId, string contentUri);
    event RoyaltyPaidDuringTransfer(uint256 indexed contentId, uint256 royaltyPaid);

    struct Access {
        uint256 expiry;
        uint256 fee;
        uint256 royaltyPerUnitValidity;
    }

    struct ServiceProvider {
        address SPOwnerAddress;
        uint256 feesCollected;
        string serviceProviderUri;
    }

    struct Content {
        address serviceProvider;
        string contentUri;
    }

    struct mintArgs {
        uint256 contentIdTemporary;
        uint256 validity;
        address subscriber;
        uint256 royaltyInPercentage;
        uint256 accessFee;
        address serviceProvider;
        string serviceProviderUri;
        string contentUri;
    }

    // contentId-->subscriber-->access
    mapping(uint256 => mapping(address => Access)) private _access;
    mapping(uint256 => Content) private _content;
    mapping(address => ServiceProvider) private _serviceProviderInfo;

    uint256 private _contentIdCounter;
    IERC20 private immutable CURRENCY;

    /// @notice Initializes the contract with the specified token address and base URI
    /// @param owner Owner's address
    /// @param tokenAddress ERC20 token address for handling payments
    /// @param baseUri Base URI for ERC1155 token metadata
    constructor(address owner, address tokenAddress, string memory baseUri) ERC1155(baseUri) Ownable(owner) {
        CURRENCY = IERC20(tokenAddress);
    }

    ///////////////////////////////////////////////////////////
    /////////// Public Functions //////////////////////////////
    ///////////////////////////////////////////////////////////

    /// @notice Sets the base URI for all tokens
    /// @param baseUri The new base URI to be set
    function setBaseUri(string calldata baseUri) public onlyOwner {
        _setURI(baseUri);
        emit NewBaseUri(baseUri);
    }

    /// @notice Allows the serviceProvider to reset the URI for all contents from them
    /// @param newServiceProviderUri The new URI to be set for the content
    /// @param serviceProvider The address of the serviceProvider
    function setServiceProviderUri(address serviceProvider, string calldata newServiceProviderUri)
        public
        onlyServiceProviderOrSPOwner(serviceProvider)
    {
        _serviceProviderInfo[serviceProvider].serviceProviderUri = newServiceProviderUri;
        emit NewServiceProviderUri(serviceProvider, newServiceProviderUri);
    }

    /// @notice Allows the serviceProvider to reset the URI for a specific content
    /// @param contentId The ID of the content
    /// @param newContentUri The new URI to be set for the content
    /// @param serviceProvider The address of the serviceProvider
    function setContentUri(address serviceProvider, uint256 contentId, string calldata newContentUri)
        public
        onlyServiceProviderOrSPOwner(serviceProvider)
    {
        if (contentId >= _contentIdCounter) revert AcceSsup_ContentDoesNotExist();
        if (_content[contentId].serviceProvider != serviceProvider) {
            revert AcceSsup_ServiceProviderMismatch();
        }

        _content[contentId].contentUri = newContentUri;
        emit NewContentUri(contentId, newContentUri);
    }

    /// @notice Retrieves the URI for a given content ID
    /// @param contentId The ID of the content to fetch URI for
    /// @return The URI of the specified content
    function uri(uint256 contentId) public view override returns (string memory) {
        string memory contentUri = _content[contentId].contentUri;
        address serviceProvider = _content[contentId].serviceProvider;
        string memory serviceProviderUri = _serviceProviderInfo[serviceProvider].serviceProviderUri;

        if (bytes(serviceProviderUri).length == 0) {
            return super.uri(contentId);
        } else {
            return bytes(contentUri).length > 0
                ? string(abi.encodePacked(serviceProviderUri, contentUri))
                : serviceProviderUri;
        }
    }

    /// @notice Sets the Owner for a specific serviceProvider
    /// @param signature The signature from the serviceProvider
    /// @param serviceProvider The serviceProvider address
    function setSPOwner(bytes calldata signature, address serviceProvider) public {
        bytes32 messageHash = keccak256(abi.encodePacked(msg.sender, serviceProvider));
        (address extractedAddress, ECDSA.RecoverError err,) = messageHash.toEthSignedMessageHash().tryRecover(signature);
        if (err != ECDSA.RecoverError.NoError) revert AcceSsup_InvalidSignature();
        if (serviceProvider != extractedAddress) {
            revert AcceSsup_ServiceProviderNotValid();
        }

        emit SPOwnerSet(serviceProvider, msg.sender);

        _serviceProviderInfo[serviceProvider].SPOwnerAddress = msg.sender;
    }

    /// @notice Mints a new access token
    /// @param arguments Arguments required for minting
    /// @param serviceProviderSignature Signature of the service provider for verification
    function mint(mintArgs calldata arguments, bytes calldata serviceProviderSignature)
        public
        VerifiedServiceProvider(arguments, serviceProviderSignature)
    {
        if (!CURRENCY.transferFrom(msg.sender, address(this), arguments.accessFee)) {
            revert AcceSsup_FeeTransferFailed();
        }

        uint256 contentId;
        uint256 contentIdCurrent = _contentIdCounter;
        if (arguments.contentIdTemporary >= contentIdCurrent) revert AcceSsup_InvalidContentId();

        if (arguments.contentIdTemporary == 0) {
            contentId = contentIdCurrent;
            setServiceProvider(contentId, arguments.serviceProviderUri, arguments.contentUri, arguments.serviceProvider);
            ++_contentIdCounter;
        } else {
            if (_content[arguments.contentIdTemporary].serviceProvider != arguments.serviceProvider) {
                revert AcceSsup_ServiceProviderMismatch();
            }
            contentId = arguments.contentIdTemporary;
        }

        updateAccess(
            contentId, arguments.subscriber, arguments.validity, arguments.royaltyInPercentage, arguments.accessFee
        );

        emit NewAccess(
            contentId,
            arguments.serviceProvider,
            arguments.validity,
            arguments.accessFee,
            arguments.subscriber,
            arguments.royaltyInPercentage
        );

        _serviceProviderInfo[arguments.serviceProvider].feesCollected += arguments.accessFee;

        _mint(arguments.subscriber, contentId, 1, "");
    }

    /// @notice Retrieves the next content ID count
    /// @return nextContentIdCount The next available content ID count
    function getNextContentIdCount() public view returns (uint256 nextContentIdCount) {
        nextContentIdCount = _contentIdCounter;
    }

    /// @notice Calculates the net royalty for a given content ID and subscriber
    /// @param contentId The ID of the content
    /// @param subscriber The address of the subscriber
    /// @return netRoyalty The calculated net royalty
    function checkNetRoyalty(uint256 contentId, address subscriber) public view returns (uint256 netRoyalty) {
        // Remove the scaling we introduced at the time of saving the royalty
        netRoyalty = (checkValidityLeft(subscriber, contentId) * _access[contentId][subscriber].royaltyPerUnitValidity);
    }

    /// @notice Allows the service provider to withdraw collected fees
    /// @param serviceProvider The address of the service provider
    function withdrawFee(address serviceProvider) public onlyServiceProviderOrSPOwner(serviceProvider) {
        uint256 payout = _serviceProviderInfo[serviceProvider].feesCollected;

        _serviceProviderInfo[serviceProvider].feesCollected = 0;
        if (payout == 0) revert AcceSsup_NoFeeToWithdraw();
        emit FeeWithdrawn(serviceProvider, msg.sender, payout);
        CURRENCY.transfer(msg.sender, payout);
    }

    function checkValidityLeft(address subscriber, uint256 contentId) public view returns (uint256 validityLeft) {
        uint256 expiry = _access[contentId][subscriber].expiry;
        // check time left in access
        expiry <= block.timestamp ? validityLeft = 0 : validityLeft = expiry - block.timestamp;
    }

    //////////////////////////////////////////////
    ////// Internal Functions ///////////////////
    /////////////////////////////////////////////

    /// @notice Logic to execute before token transfer
    /// @param from The address transferring the token
    /// @param to The recipient address
    /// @param ids Array of token IDs
    /// @param values Array of token amounts
    function _update(address from, address to, uint256[] memory ids, uint256[] memory values)
        internal
        virtual
        override
    {
        if (from != address(0) && from != to) {
            uint256 netRoyalty;

            for (uint256 i = 0; i < ids.length; ++i) {
                _access[ids[i]][to] = Access({
                    expiry: _access[ids[i]][from].expiry + checkValidityLeft(to, ids[i]),
                    fee: _access[ids[i]][from].fee,
                    royaltyPerUnitValidity: _access[ids[i]][from].royaltyPerUnitValidity
                });

                uint256 royalty = checkNetRoyalty(ids[i], from);
                emit RoyaltyPaidDuringTransfer(ids[i], royalty);
                netRoyalty += royalty;

                _access[ids[i]][from] = Access({expiry: 0, fee: 0, royaltyPerUnitValidity: 0});
                address serviceProvider = _content[ids[i]].serviceProvider;
                _serviceProviderInfo[serviceProvider].feesCollected += netRoyalty;
            }

            if (!CURRENCY.transferFrom(msg.sender, address(this), netRoyalty)) revert AcceSsup_PayRoyaltyFeeFailed();
        }
        // call base implementation
        super._update(from, to, ids, values);
    }

    /// @notice Updates access details for a given content and subscriber
    /// @param contentId The ID of the content for which access is being updated
    /// @param subscriber The address of the subscriber whose access is being updated
    /// @param validity The validity period for the access
    /// @param royaltyInPercentage The royalty percentage to be applied
    /// @param accessFee The fee associated with the access
    /// @dev This function updates the access expiry, fee, and royalty per unit validity for a given content and subscriber
    function updateAccess(
        uint256 contentId,
        address subscriber,
        uint256 validity,
        uint256 royaltyInPercentage,
        uint256 accessFee
    ) internal {
        _access[contentId][subscriber] = Access({
            expiry: block.timestamp + validity + checkValidityLeft(subscriber, contentId),
            fee: accessFee,
            royaltyPerUnitValidity: (validity == 0 ? 0 : (royaltyInPercentage * accessFee) / 10 ** 3 / validity)
        });
    }

    function setServiceProvider(
        uint256 contentId,
        string memory serviceProviderUri,
        string memory contentUri,
        address serviceProvider
    ) internal {
        if (
            bytes(_serviceProviderInfo[serviceProvider].serviceProviderUri).length == 0
                && bytes(serviceProviderUri).length != 0
        ) {
            _serviceProviderInfo[serviceProvider].serviceProviderUri = serviceProviderUri;
            emit NewServiceProviderUri(serviceProvider, serviceProviderUri);
        }

        if (
            bytes(_serviceProviderInfo[serviceProvider].serviceProviderUri).length != 0 && bytes(contentUri).length != 0
        ) {
            _content[contentId].contentUri = contentUri;
            emit NewContentUri(contentId, contentUri);
        }

        _content[contentId].serviceProvider = serviceProvider;
        emit NewContent(serviceProvider, contentId);
    }

    // Modifiers:

    /// @notice Verifies the signature of a service provider for minting operations
    /// @dev This modifier is used to ensure that the mint operation is initiated by a valid service provider
    /// @param arguments The minting arguments including details like content ID, validity, royalty, fee, and service provider information
    /// @param signature The digital signature provided by the service provider
    modifier VerifiedServiceProvider(mintArgs calldata arguments, bytes calldata signature) {
        // Hash the concatenation of contract address and mintArgs
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                address(this),
                arguments.contentIdTemporary,
                arguments.validity,
                arguments.royaltyInPercentage,
                arguments.accessFee,
                arguments.serviceProvider,
                arguments.serviceProviderUri,
                arguments.contentUri
            )
        );

        // Verify that the message hash was signed by the service provider
        if (arguments.serviceProvider != messageHash.toEthSignedMessageHash().recover(signature)) {
            revert AcceSsup_ServiceProviderNotValid();
        }

        _; // Continue execution
    }

    /// @notice Ensures that the caller is either the service provider or the owner of the service provider
    /// @param serviceProvider The address of the service provider
    modifier onlyServiceProviderOrSPOwner(address serviceProvider) {
        address spOwner = _serviceProviderInfo[serviceProvider].SPOwnerAddress;
        if (spOwner != address(0)) {
            if (msg.sender != spOwner) revert AcceSsup_Unauthorized();
        } else {
            if (msg.sender != serviceProvider) revert AcceSsup_Unauthorized();
        }
        _;
    }
}
