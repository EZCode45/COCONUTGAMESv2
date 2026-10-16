
export async function onRequestGet({ env }) {
  try {
    const result = await env.DB.prepare(
      "SELECT key, value FROM site_settings"
    ).all();

    const settings = Object.fromEntries(
      result.results.map(row => [row.key, row.value])
    );

    return Response.json({
      title: settings.title || "COCONUT",
      description:
        settings.description || "Launch games in cloak mode",
      lessonsPath:
        settings.lessonsPath || "/pages/lessons/lessons.html"
    }, {
      headers: {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff"
      }
    });
  } catch {
    return Response.json(
      { error: "Unable to load site configuration" },
      { status: 500 }
    );
  }
}
