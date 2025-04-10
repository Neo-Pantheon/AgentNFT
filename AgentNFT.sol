// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract AgentNFT is ERC721Enumerable, Ownable {
    using Counters for Counters.Counter;
    
    // Counters
    Counters.Counter private _tokenIdCounter;
    
    // NEOX token
    IERC20 public neoxToken;
    
    // Registry contract
    address public registry;
    
    // Agent info
    struct AgentInfo {
        uint256 agentId;     // ID from registry
        uint8 agentType;     // 0=Builder, 1=Researcher, 2=Socialite
        string name;         // Agent name
        string symbol;       // Short identifier
        address creator;     // Original creator
        string customURI;    // Custom token URI
    }
    
    // Mapping: tokenId => AgentInfo
    mapping(uint256 => AgentInfo) public agentInfo;
    
    // Mapping: agentId => tokenIds
    mapping(uint256 => uint256[]) public agentTokens;
    
    // Revenue tracking
    mapping(uint256 => uint256) public unclaimedRevenue;
    mapping(uint256 => uint256) public totalRevenueClaimed;
    
    // Usage tracking
    mapping(uint256 => uint256) public totalUsageCount;
    
    // Custom token URIs
    mapping(uint256 => string) private _tokenURIs;
    
    // Events
    event AgentCreated(uint256 indexed tokenId, uint256 indexed agentId, address indexed creator, string customURI);
    event RevenueClaimed(uint256 indexed tokenId, address indexed owner, uint256 amount);
    event RevenueDistributed(uint256 indexed agentId, uint256 amount);
    event AgentUsed(uint256 indexed agentId, address indexed user);
    
    constructor(address _neoxToken) ERC721("Neo Pantheon Agent", "NPAG") Ownable(msg.sender) {
        neoxToken = IERC20(_neoxToken);
    }
    
    function setRegistry(address _registry) external onlyOwner {
        registry = _registry;
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
            customURI: customURI
        });
        
        agentTokens[agentId].push(tokenId);
        
        // Set custom token URI
        _tokenURIs[tokenId] = customURI;
        
        emit AgentCreated(tokenId, agentId, to, customURI);
        
        return tokenId;
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
        require(tokens.length > 0, "No tokens for agent");
        
        uint256 amountPerToken = amount / tokens.length;
        require(amountPerToken > 0, "Amount too small");
        
        for (uint256 i = 0; i < tokens.length; i++) {
            unclaimedRevenue[tokens[i]] += amountPerToken;
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
