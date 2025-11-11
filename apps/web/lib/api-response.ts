export interface ApiResponse<T = any> {
  ok: boolean;
  data?: T;
  error?: string;
}

export function successResponse<T>(data: T): ApiResponse<T> {
  return {
    ok: true,
    data,
  };
}

export function errorResponse(error: string): ApiResponse {
  return {
    ok: false,
    error,
  };
}
