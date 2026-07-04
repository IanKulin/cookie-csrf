import js from "@eslint/js";
import prettier from "eslint-config-prettier";

export default [
  js.configs.recommended,
  prettier,
  {
    ignores: ["node_modules/", "example/", "examples/"],
  },
];
