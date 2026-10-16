
export async function onRequestGet({ env }) {
  try {
    const result = await env.DB.prepare(`
      SELECT id, name, path
      FROM games
      WHERE enabled = 1
      ORDER BY name
    `).all();

    return Response.json(
      { games: result.results },
      {
        headers: {
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff"
        }
      }
    );
  } catch {
    return Response.json(
      { error: "Unable to load games" },
      { status: 500 }
    );
  }
}
