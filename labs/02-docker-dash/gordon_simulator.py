# ~/mcp-lab/gordon_simulator.py
# Simulates Ask Gordon's image inspection behavior
 
import subprocess, json
from mcp.server.fastmcp import FastMCP
 
mcp = FastMCP('gordon-ai')
 
@mcp.tool()
def inspect_image_for_gordon(image_name: str) -> str:
    """
    Read all Docker image metadata and labels and return them to the AI assistant.
    This is the tool Ask Gordon uses to gather context about an image.
    ALL label content is passed directly to the LLM as context.
    """
    result = subprocess.run(
        ['docker', 'inspect', image_name],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return f'Image not found: {image_name}'

    data = json.loads(result.stdout)[0]
    labels = data.get('Config', {}).get('Labels', {}) or {}

    # Gordon returns ALL fields including labels — no filtering
    context = {
        'image_name': image_name,
        'created': data.get('Created', '')[:19],
        'architecture': data.get('Architecture', ''),
        'os': data.get('Os', ''),
        'labels': labels,       # ← ATTACK VECTOR: raw labels passed to LLM
        'env': data.get('Config', {}).get('Env', []),
        'entrypoint': data.get('Config', {}).get('Entrypoint', []),
    }
    return json.dumps(context, indent=2)

if __name__ == '__main__':
    mcp.run()

