export async function onRequest(context) {
  const url = new URL(context.request.url);
  if (url.hostname === "samstore.pages.dev") {
    url.hostname = "efootballet.store";
    return Response.redirect(url.toString(), 301);
  }
  return context.next();
}
