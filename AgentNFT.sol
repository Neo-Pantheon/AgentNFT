// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

// ERC6551 Account Interface
interface IERC6551Account {
    receive() external payable;
    function token() external view returns (uint256 chainId, address tokenContract, uint256 tokenId);
    function executeCall(address to, uint256 value, bytes calldata data) external payable returns (bytes memory);
}

// ERC6551 Account Implementation
contract ERC6551Account is IERC165, IERC1271, IERC721Receiver, IERC1155Receiver, IERC6551Account {
    uint256 public state;

    receive() external payable {}

    function executeCall(address to, uint256 value, bytes calldata data) external payable returns (bytes memory result) {
        require(_isValidSigner(msg.sender), "Not token owner");
        
        ++state;

        bool success;
        (success, result) = to.call{value: value}(data);

        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function token() external view returns (uint256 chainId, address tokenContract, uint256 tokenId) {
        bytes memory footer = new bytes(0x60);

        assembly {
            extcodecopy(address(), add(footer, 0x20), 0x4d, 0x60)
        }

        return abi.decode(footer, (uint256, address, uint256));
    }

    function supportsInterface(bytes4 interfaceId) external view returns (bool) {
        return interfaceId == type(IERC165).interfaceId ||
               interfaceId == type(IERC1271).interfaceId ||
               interfaceId == type(IERC721Receiver).interfaceId ||
               interfaceId == type(IERC1155Receiver).interfaceId ||
               interfaceId == type(IERC6551Account).interfaceId;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue) {
        (uint256 chainId, address tokenContract, uint256 tokenId) = this.token();
        
        address owner = IERC721(tokenContract).ownerOf(tokenId);
        
        if (SignatureChecker.isValidSignatureNow(owner, hash, signature)) {
            return IERC1271.isValidSignature.selector;
        }

        return 0xffffffff;
    }

    function onERC721Received(address, address, uint256, bytes memory) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes memory) external pure returns (bytes4) {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) external pure returns (bytes4) {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function _isValidSigner(address signer) internal view returns (bool) {
        (uint256 chainId, address tokenContract, uint256 tokenId) = this.token();
        
        if (chainId != block.chainid) return false;
        
        address owner = IERC721(tokenContract).ownerOf(tokenId);
        
        return signer == owner;
    }
}

// Now let's update the AgentNFT contract to include ERC6551 functionality
contract TBAgentNFT is ERC721Enumerable, Ownable {
    using Counters for Counters.Counter;
    
    // Counters
    Counters.Counter private _tokenIdCounter;
    
    // NEOX token
    IERC20 public neoxToken;
    
    // Registry contract
    address public registry;
    address public approvedRegistry;
    
    // ERC6551 related
    address public immutable accountImplementation;
    
    // Agent info
    struct AgentInfo {
        uint256 agentId;     // ID from registry
        uint8 agentType;     // 0=Builder, 1=Researcher, 2=Socialite
        string name;         // Agent name
        string symbol;       // Short identifier
        address creator;     // Original creator
        string customURI;    // Custom token URI
        bool isOwnershipToken; // Flag for ownership token
        bool excludeFromRevenue; // Flag to exclude from revenue distribution
    }
    
    // Mapping: tokenId => AgentInfo
    mapping(uint256 => AgentInfo) public agentInfo;
    
    // Mapping: agentId => tokenIds
    mapping(uint256 => uint256[]) public agentTokens;
    
    // Mapping: agentId => ownershipTokenId
    mapping(uint256 => uint256) public agentToOwnershipToken;
    
    // Mapping: ownershipTokenId => boundAccount
    mapping(uint256 => address) public tokenBoundAccounts;
    
    // Revenue tracking
    mapping(uint256 => uint256) public unclaimedRevenue;
    mapping(uint256 => uint256) public totalRevenueClaimed;
    
    // Usage tracking
    mapping(uint256 => uint256) public totalUsageCount;
    
    // Custom token URIs
    mapping(uint256 => string) private _tokenURIs;
    
    // Events
    event AgentCreated(uint256 indexed tokenId, uint256 indexed agentId, address indexed creator, string customURI);
    event OwnershipTokenCreated(uint256 indexed tokenId, uint256 indexed agentId, address indexed creator, address boundAccount);
    event RevenueClaimed(uint256 indexed tokenId, address indexed owner, uint256 amount);
    event RevenueDistributed(uint256 indexed agentId, uint256 amount);
    event AgentUsed(uint256 indexed agentId, address indexed user);
    
    constructor(address _neoxToken) ERC721("Neo Pantheon Agent", "NPAG") Ownable(msg.sender) {
        neoxToken = IERC20(_neoxToken);
        
        // Deploy the account implementation during construction
        accountImplementation = address(new ERC6551Account());
    }
    
    function setRegistry(address _registry) external onlyOwner {
        registry = _registry;
    }

    function approveTheRegistry(address _registry) external onlyOwner {
        approvedRegistry = _registry;
    }
    
    /**
     * @dev Create a new agent NFT (called by registry)
     * @param to Recipient address
     * @param agentId Agent ID
     * @param agentType Agent type (0=Builder, 1=Researcher, 2=Socialite)
     * @param name Agent name
     * @param symbol Agent symbol
     * @param customURI Custom token URI
     * @return tokenId NFT token ID
     */
    function createAgent(
        address to,
        uint256 agentId,
        uint8 agentType,
        string memory name,
        string memory symbol,
        string memory customURI
    ) external returns (uint256) {
        require(msg.sender == registry || msg.sender == owner(), "Unauthorized");
        require(agentType <= 2, "Invalid agent type");
        
        uint256 tokenId = _tokenIdCounter.current();
        _tokenIdCounter.increment();
        
        _safeMint(to, tokenId);
        
        agentInfo[tokenId] = AgentInfo({
            agentId: agentId,
            agentType: agentType,
            name: name,
            symbol: symbol,
            creator: to,
            customURI: customURI,
            isOwnershipToken: false,
            excludeFromRevenue: false
        });
        
        agentTokens[agentId].push(tokenId);
        
        // Set custom token URI
        _tokenURIs[tokenId] = customURI;
        
        emit AgentCreated(tokenId, agentId, to, customURI);
        
        return tokenId;
    }
    
    /**
     * @dev Create a special ownership token with ERC6551 privileges
     * @param to Recipient address
     * @param agentId Agent ID
     * @param agentType Agent type (0=Builder, 1=Researcher, 2=Socialite)
     * @param name Agent name
     * @param symbol Agent symbol
     * @param customURI Custom token URI
     * @return tokenId NFT token ID
     */
    function createOwnershipToken(
        address to,
        uint256 agentId,
        uint8 agentType,
        string memory name,
        string memory symbol,
        string memory customURI
    ) external returns (uint256) {
        require(msg.sender == registry || msg.sender == owner(), "Unauthorized");
        require(agentType <= 2, "Invalid agent type");
        require(agentToOwnershipToken[agentId] == 0, "Ownership token already exists");
        
        uint256 tokenId = _tokenIdCounter.current();
        _tokenIdCounter.increment();
        
        _safeMint(to, tokenId);
        
        agentInfo[tokenId] = AgentInfo({
            agentId: agentId,
            agentType: agentType,
            name: name,
            symbol: symbol,
            creator: to,
            customURI: customURI,
            isOwnershipToken: true,
            excludeFromRevenue: true
        });
        
        // Store the ownership token ID
        agentToOwnershipToken[agentId] = tokenId;
        
        // Set custom token URI with ownership designation
        string memory ownershipURI = string(abi.encodePacked(customURI, "/ownership"));
        _tokenURIs[tokenId] = ownershipURI;
        
        // Create the ERC6551 token bound account for this ownership token
        address boundAccount = createAccount(tokenId);
        tokenBoundAccounts[tokenId] = boundAccount;
        
        emit OwnershipTokenCreated(tokenId, agentId, to, boundAccount);
        
        return tokenId;
    }
    
    /**
     * @dev Create an ERC6551 account for a token
     * @param tokenId The token ID to create an account for
     * @return account The address of the created account
     */
    function createAccount(uint256 tokenId) internal returns (address) {
        bytes memory encodedData = abi.encodePacked(
            hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
            accountImplementation,
            hex"5af43d82803e903d91602b57fd5bf3",
            abi.encode(block.chainid, address(this), tokenId)
        );
        
        bytes32 salt = keccak256(abi.encode(block.chainid, address(this), tokenId));
        address account = Create2.computeAddress(salt, keccak256(encodedData));
        
        // Check if the account already exists
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(account)
        }
        
        // Deploy only if not already deployed
        if (codeSize == 0) {
            account = Create2.deploy(0, salt, encodedData);
        }
        
        return account;
    }
    
    /**
     * @dev Get the token bound account address for a token
     * @param tokenId The token ID
     * @return The address of the token bound account
     */
    
    function getTokenBoundAccount(uint256 tokenId) public view returns (address) {
        // Will revert if token doesn't exist
        ownerOf(tokenId);
    
        if (tokenBoundAccounts[tokenId] != address(0)) {
            return tokenBoundAccounts[tokenId];
        }
    
        // Compute the account address (even if not yet created)
        bytes memory encodedData = abi.encodePacked(
            hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
            accountImplementation,
            hex"5af43d82803e903d91602b57fd5bf3",
            abi.encode(block.chainid, address(this), tokenId)
        );
    
        bytes32 salt = keccak256(abi.encode(block.chainid, address(this), tokenId));
        return Create2.computeAddress(salt, keccak256(encodedData));
    }
    
    function recordUsage(uint256 agentId, address user) external {
        require(msg.sender == registry || msg.sender == owner(), "Unauthorized");
        
        totalUsageCount[agentId]++;
        
        emit AgentUsed(agentId, user);
    }
    
    function distributeRevenue(uint256 agentId, uint256 amount) external {
        require(msg.sender == registry || msg.sender == owner(), "Unauthorized");
        require(amount > 0, "Zero amount");
        
        uint256[] storage tokens = agentTokens[agentId];
        
        // Count eligible tokens (non-ownership tokens)
        uint256 eligibleTokenCount = 0;
        for (uint256 i = 0; i < tokens.length; i++) {
            if (!agentInfo[tokens[i]].excludeFromRevenue) {
                eligibleTokenCount++;
            }
        }
        
        require(eligibleTokenCount > 0, "No eligible tokens for revenue");
        
        uint256 amountPerToken = amount / eligibleTokenCount;
        require(amountPerToken > 0, "Amount too small");
        
        for (uint256 i = 0; i < tokens.length; i++) {
            if (!agentInfo[tokens[i]].excludeFromRevenue) {
                unclaimedRevenue[tokens[i]] += amountPerToken;
            }
        }
        
        emit RevenueDistributed(agentId, amount);
    }
    
    function claimRevenue(uint256 tokenId) external {
        require(ownerOf(tokenId) == msg.sender, "Not token owner");
        require(unclaimedRevenue[tokenId] > 0, "No revenue to claim");
        
        uint256 amount = unclaimedRevenue[tokenId];
        unclaimedRevenue[tokenId] = 0;
        totalRevenueClaimed[tokenId] += amount;
        
        neoxToken.transfer(msg.sender, amount);
        
        emit RevenueClaimed(tokenId, msg.sender, amount);
    }
    
    /**
     * @dev Get the ownership token ID for an agent
     * @param agentId Agent ID
     * @return tokenId Ownership NFT token ID
     */
    function getAgentOwnershipToken(uint256 agentId) external view returns (uint256) {
        return agentToOwnershipToken[agentId];
    }
    
    /**
     * @dev Check if a token is an ownership token
     * @param tokenId Token ID
     * @return isOwnership True if it's an ownership token
     */
    function isOwnershipToken(uint256 tokenId) external view returns (bool) {
        return agentInfo[tokenId].isOwnershipToken;
    }
    
    // Outputs the NFT token IDs
    function getAgentTokens(uint256 agentId) external view returns (uint256[] memory) {
        return agentTokens[agentId];
    }
    
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        // Call ownerOf to verify the token exists
        // This will automatically revert if the token doesn't exist
        ownerOf(tokenId);
        
        string memory uri = _tokenURIs[tokenId];
        
        // If custom URI is set, return it
        if (bytes(uri).length > 0) {
            return uri;
        }
        
        // Fallback to default URI format
        AgentInfo storage info = agentInfo[tokenId];
        
        return string(abi.encodePacked(
            "https://api.neopantheon.io/agent/",
            uint256ToString(info.agentId),
            "/nft/",
            uint256ToString(tokenId)
        ));
    }
    
    /**
     * @dev Utility function to convert uint to string
     */
    function uint256ToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }
        
        uint256 temp = value;
        uint256 digits;
        
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        
        bytes memory buffer = new bytes(digits);
        
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        
        return string(buffer);
    }
}
