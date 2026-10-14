import { createClient } from "@supabase/supabase-js";
import { config } from "./config.js";

// Service-role client: bypasses RLS, so it must only ever live on the server.
export const supabase = createClient(config.supabaseUrl, config.supabaseServiceKey, {
  auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
});
