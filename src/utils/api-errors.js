class ApiError extends Error {
    constructor(statusCode, message, error = [],stack = '') {
      super(message);
      this.name = this.constructor.name;
      this.statusCode = statusCode;
      this.error = error;
      this.success = false;
      if (stack) {
        this.stack = stack;
      } else {
        Error.captureStackTrace(this, this.constructor);
      }
    }
  }
  
  export { ApiError }
  