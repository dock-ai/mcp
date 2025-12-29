# Dock AI MCP

MCP server for [Dock AI](https://dockai.co) - discover MCP endpoints for real-world entities.

## What is this?

This MCP server allows AI agents to discover which MCP servers can interact with a given entity (restaurant, hotel, salon, etc.) by querying the Dock AI registry.

## Installation

```bash
# Using uv (recommended)
uv pip install dock-ai-mcp

# Using pip
pip install dock-ai-mcp
```

## Usage

### With Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dock-ai": {
      "command": "uvx",
      "args": ["dock-ai-mcp"]
    }
  }
}
```

### With other MCP clients

```bash
# Run directly
uvx dock-ai-mcp

# Or if installed
dock-ai-mcp
```

## Tools

### `resolve_domain`

Resolve a domain to its MCP endpoints.

**Input:**
- `domain` (string): The domain to resolve (e.g., "example-restaurant.com")

**Output:**
```json
{
  "entity": {
    "domain": "example-restaurant.com",
    "name": "Example Restaurant",
    "category": "restaurant",
    "location": { "city": "Paris", "country": "FR" },
    "verification_level": 2
  },
  "mcps": [
    {
      "provider": "booking-provider",
      "endpoint": "https://mcp.booking-provider.com",
      "entity_id": "entity-123",
      "capabilities": ["reservations", "availability"],
      "verification": { "level": 2, "method": "dual_attestation" }
    }
  ]
}
```

## Example

```
User: "I want to book a table at example-restaurant.com"

Agent: [calls resolve_domain("example-restaurant.com")]
       -> Gets MCP endpoint for reservations
       -> Connects to the MCP server
       -> Books the table
```

## License

MIT
