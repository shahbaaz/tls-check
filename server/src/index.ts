import { createApp } from "./app.ts";

const host = "127.0.0.1"; // only Nginx should reach the server
const port = Number(process.env.PORT ?? 3000);

createApp().listen(port, host, (err) => {
  if (err) throw err;
  console.log(`Server listening on http://${host}:${port}`);
});
