import Mailgen from "mailgen";
import nodemailer from "nodemailer";
import asyncHandler from "./async-handler.js";
import { ApiError } from "./api-errors.js";


const sendMail = async (options) => {
  var mailGenerator = new Mailgen({
    theme: "default",
    product: {
      name: "Task Manager",
      link: "https://mailgen.js/",
      // Optional product logo
      // logo: 'https://mailgen.js/img/logo.png'
    },
  });
  var emailText = mailGenerator.generatePlaintext(options.mailgenContent);
  var emailHtml = mailGenerator.generate(options.mailgenContent);

  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_HOST,
    port: process.env.MAILTRAP_PORT,
    secure: false, // true for port 465, false for other ports
    auth: {
      user: process.env.MAILTRAP_USER,
      pass: process.env.MAILTRAP_PASS,
    },
  });

  const mailOptions = {
    from: "taskmeneger@task.com", // sender address
    to: options.email, // list of receivers
    subject: options.subject, // Subject line
    text: emailText, // plain text body
    html: emailHtml, // html body
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    ApiError("Email not sent", 500);
  }
};

const verificationMailGenContent = asyncHandler(async (username, verificationUrl) => {
  return {
    body: {
      name: username,
      intro: "Welcome to Task Manager! We're very excited to have you on board.",
      action: {
        instruction: "Please verify your email address to get started.",
        button: {
          color: "#22BC66",
          text: "Verify your email",
          link: verificationUrl,
        },
      },
      outro: "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
});

const forgotPasswordMailGenContent = asyncHandler(async (username, passwordResetUrl) => {
  return {
    body: {
      name: username,
      intro: "We got a request to reset your password",
      action: {
        instruction: "Please click the button below to rest your password.",
        button: {
          color: "#22BC66",
          text: "Reset your password",
          link: passwordResetUrl,
        },
      },
      outro: "Need help, or have questions? Just reply to this email, we'd love to help.",
    },
  };
});
