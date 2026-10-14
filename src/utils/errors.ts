export class AppError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public fields?: Record<string, string>,
  ) {
    super(message);
  }
}

export const unauthorized = (message = "Authentication required.") =>
  new AppError(401, "UNAUTHORIZED", message);

export const internal = (context: string, err?: unknown) => {
  console.error(`[db] ${context}`, err);
  return new AppError(500, "INTERNAL", "Something went wrong.");
};
