export async function onRequestGet() {
  return Response.json({
    app: "KON-CHAT",
    version: "0.2"
  });
}
