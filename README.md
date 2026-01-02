# Dock AI MCP

MCP server for [Dock AI](https://dockai.co) - discover MCP endpoints for real-world entities.

## What is this?

Dock AI is a registry that maps businesses to their MCP connectors. This MCP server allows AI agents to discover which MCP servers can interact with a given entity (restaurant, hotel, salon, etc.) by querying the Dock AI registry.

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

Check if an MCP connector exists for a business domain.

**Input:**
- `domain` (string): The business domain to resolve (e.g., "example-restaurant.com")

**Output:**
```json
{
  "domain": "example-restaurant.com",
  "entities": [
    {
      "name": "Example Restaurant",
      "path": null,
      "location": { "city": "Paris", "country": "FR" },
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
  ],
  "claude_desktop_config": {
    "mcpServers": {
      "booking-provider": { "url": "https://mcp.booking-provider.com/mcp" }
    }
  }
}
```

## Examples

### Example 1: Restaurant Reservation

```
User: "Book a table at Gloria Osteria Paris"

Agent: [searches web for "Gloria Osteria Paris official website"]
       -> Finds domain: gloria-osteria.com
       [calls resolve_domain("gloria-osteria.com")]
       -> Gets MCP endpoint for SevenRooms
       -> Connects to the MCP server
       -> Books the table
```

### Example 2: Hotel Booking

```
User: "I need a room at The Hoxton in London"

Agent: [searches web for "The Hoxton London website"]
       -> Finds domain: thehoxton.com
       [calls resolve_domain("thehoxton.com")]
       -> Gets MCP endpoints for available booking providers
       -> Uses the MCP to check availability and book
```

### Example 3: Business with No MCP Yet

```
User: "Book at Le Paris Paris restaurant"

Agent: [calls resolve_domain("leparisparis.fr")]
       -> Response shows pending_providers: [{ "provider": "thefork", ... }]
       -> Informs user: "This restaurant uses TheFork for reservations,
          but TheFork hasn't published an MCP connector yet.
          You can book directly on TheFork's website."
```

## Support

- **Documentation**: [dockai.co/docs](https://dockai.co/docs)
- **Issues**: [GitHub Issues](https://github.com/dock-ai/mcp/issues)
- **Email**: support@dockai.co

## Privacy

This MCP server queries the Dock AI registry API to resolve domains. No user data is collected or stored. See our [Privacy Policy](https://dockai.co/privacy).

## License

MIT
