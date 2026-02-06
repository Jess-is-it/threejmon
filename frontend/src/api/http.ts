export type ApiError = { message: string };

export async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { Accept: "application/json" }, cache: "no-store" });
  if (!res.ok) {
    let detail = "";
    try {
      const body = (await res.json()) as any;
      if (body?.error) detail = String(body.error);
    } catch {
      // ignore
    }
    throw { message: detail || `Request failed (${res.status})` } satisfies ApiError;
  }
  return (await res.json()) as T;
}

