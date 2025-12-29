# Dock AI MCP

MCP server for [Dock AI](https://dockai.co) - discover MCP endpoints for real-world entities.

## What is this?

This MCP server allows AI agents to discover which MCP servers can interact with a given entity (restaurant, hotel, salon, etc.) by querying the Dock AI registry.

## Hosted Version

Use the hosted version at `https://mcp.dockai.co/mcp` - no installation required.

```json
{
  "mcpServers": {
    "dock-ai": {
      "url": "https://mcp.dockai.co/mcp"
    }
  }
}
```

## Self-Hosting

### Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/dock-ai/mcp)

### Run locally

```bash
# Using uvx
uvx dock-ai-mcp

# Or install and run
pip install dock-ai-mcp
dock-ai-mcp
```

The server starts on `http://0.0.0.0:8080/mcp`.

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
