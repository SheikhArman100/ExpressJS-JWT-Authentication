const { z } = require("zod");
const registerSchema = z.object({
  body: z
    .object({
      username: z.string({
        required_error: "Username is required",
      }),
      email: z
        .string({
          required_error: "Email is required",
        })
        .email({
          message: "Not a valid email",
        }),
      password: z
        .string({
          required_error: "Password is required",
        })
        .min(6, {
          message: "Password too short - should be 6 chars minimum",
        }),
      passwordConfirmation: z.string({
        required_error: "Password confirmation is required",
      }),
    })
    .refine((data) => data.password === data.passwordConfirmation, {
      message: "Passwords do not match",
      path: ["passwordConfirmation"],
    }),
});

const loginSchema = z.object({
  body: z.object({
    email: z
      .string({
        required_error: "Email is required",
      })
      .email({
        message: "Not a valid email",
      }),
    password: z
      .string({
        required_error: "Password is required",
      })
      .min(6, {
        message: "Password too short - should be 6 chars minimum",
      }),
  }),
});

module.exports = { registerSchema,loginSchema };
