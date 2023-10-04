import { Elysia, t } from "elysia";
import { LuciaError } from "lucia";
import { serializeCookie } from "lucia/utils";
import { googlAuth } from "../auth";
import { config } from "../config";
import { ctx } from "../context";
import { redirect } from "../lib";

class DuplicateEmailError extends Error {
  constructor() {
    super("Duplicate email");
  }
}

export const authController = new Elysia({
  prefix: "/auth",
})
  .use(ctx)
  .get("/signout", async (ctx) => {
    const authRequest = ctx.auth.handleRequest(ctx);
    const session = await authRequest.validate();
    ctx.set;
    if (!session) {
      ctx.set.status = "Unauthorized";
      redirect(
        {
          set: ctx.set,
          headers: ctx.set.headers,
        },
        "/",
      );
      return;
    }

    await ctx.auth.invalidateSession(session.sessionId);

    const sessionCookie = ctx.auth.createSessionCookie(null);

    ctx.set.headers["Set-Cookie"] = sessionCookie.serialize();
    redirect(
      {
        set: ctx.set,
        headers: ctx.set.headers,
      },
      "/",
    );
  })
  .get("/signin/google", async (ctx) => {
    const [url, state] = await googlAuth.getAuthorizationUrl();
    const state_cookie = serializeCookie("state_cookie", state, {
      maxAge: 60 * 60 * 24,
      httpOnly: true,
      secure: config.env.NODE_ENV === "production",
      path: "/",
    });
  });
