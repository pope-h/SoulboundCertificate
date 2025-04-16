// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title SoulboundCertificate
 * @dev A soulbound non-transferable ERC721 token for Lisk Bootcamp Certificates
 */
contract SoulboundCertificate is ERC721URIStorage, AccessControl {
    uint256 private _tokenIds;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");

    // Track if an address has already minted a certificate
    mapping(address => bool) private _hasMinted;

    // Event for transfer attempts
    event TransferAttemptPrevented(address indexed from, address indexed to, uint256 indexed tokenId);

    constructor() ERC721("Lisk Bootcamp Certificate", "LBC") {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    /**
     * @dev Add multiple addresses to the whitelist
     * @param addresses Array of addresses to whitelist
     */
    function addToWhitelist(address[] memory addresses)
        public
        onlyRole(ADMIN_ROLE)
    {
        for (uint256 i = 0; i < addresses.length; i++) {
            grantRole(WHITELIST_ROLE, addresses[i]);
        }
    }

    /**
     * @dev Remove multiple addresses from the whitelist
     * @param addresses Array of addresses to remove from whitelist
     */
    function removeFromWhitelist(address[] memory addresses)
        public
        onlyRole(ADMIN_ROLE)
    {
        for (uint256 i = 0; i < addresses.length; i++) {
            revokeRole(WHITELIST_ROLE, addresses[i]);
        }
    }

    /**
     * @dev Mint a new certificate NFT to the caller
     * @param tokenURI URI for the token metadata
     * @return The newly minted token ID
     */
    function mintCertificate(string memory tokenURI)
        public
        onlyRole(WHITELIST_ROLE)
        returns (uint256)
    {
        require(!_hasMinted[msg.sender], "Address has already minted a certificate");
        
        _tokenIds++;
        uint256 newTokenId = _tokenIds;
        
        _safeMint(msg.sender, newTokenId);
        _setTokenURI(newTokenId, tokenURI);
        
        _hasMinted[msg.sender] = true;
        
        return newTokenId;
    }

    /**
     * @dev Burn a certificate NFT
     * @param tokenId The token ID to burn
     */
    function burnCertificate(uint256 tokenId)
        public
        onlyRole(ADMIN_ROLE)
    {
        _burn(tokenId);
    }

    /**
     * @dev Override _update to enforce soulbound property
     */
    function _update(address to, uint256 tokenId, address auth)
        internal
        virtual
        override
        returns (address)
    {
        address from = _ownerOf(tokenId);
        if (from != address(0) && to != address(0)) {
            emit TransferAttemptPrevented(from, to, tokenId);
            revert("Soulbound: Transfers are not allowed");
        }
        return super._update(to, tokenId, auth);
    }

    /**
     * @dev Prevent token transfers to enforce soulbound property
     */
    function transferFrom(address from, address to, uint256 tokenId)
        public
        virtual
        override(ERC721, IERC721)
    {
        if (from != address(0) && to != address(0)) {
            emit TransferAttemptPrevented(from, to, tokenId);
            revert("Soulbound: Transfers are not allowed");
        }
        super.transferFrom(from, to, tokenId);
    }

    /**
     * @dev Prevent safe token transfers with data to enforce soulbound property
     */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)
        public
        virtual
        override(ERC721, IERC721)
    {
        if (from != address(0) && to != address(0)) {
            emit TransferAttemptPrevented(from, to, tokenId);
            revert("Soulbound: Transfers are not allowed");
        }
        super.safeTransferFrom(from, to, tokenId, data);
    }

    /**
     * @dev Custom implementation to prevent approvals
     */
    function approve(address, uint256) public virtual override(ERC721, IERC721) {
        revert("Soulbound: Approvals are not allowed");
    }

    /**
     * @dev Custom implementation to prevent approvals for all
     */
    function setApprovalForAll(address, bool) public virtual override(ERC721, IERC721) {
        revert("Soulbound: Approvals are not allowed");
    }

    /**
     * @dev Implementation of the {IERC165} interface.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC721URIStorage, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}