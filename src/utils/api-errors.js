class ApiError extends Error {
  constructor(statusCode, message, error = [], stack = '') {
    super(message);

    // Set the name of the error to be the class name
    this.name = this.constructor.name;

    // Assign the status code and custom error details
    this.statusCode = statusCode;
    this.error = error;
    this.success = false;

    // Optionally capture stack trace if provided or default
    if (stack) {
      this.stack = stack;
    } else {
      // Capture stack trace from the current error
      Error.captureStackTrace(this, this.constructor);
    }
  }

  // Optionally you can add a method to format the error better for debugging or logging
  logError() {
    // In a real-world scenario, this could be sent to a logging service
    console.error(`${this.name}: ${this.message} [StatusCode: ${this.statusCode}]`);
    if (this.stack) {
      console.error(this.stack);
    }
  }
}

export { ApiError };
