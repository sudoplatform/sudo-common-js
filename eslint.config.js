const { defineConfig } = require('eslint/config')

const prettier = require('eslint-plugin-prettier')
const globals = require('globals')
const typescriptEslint = require('@typescript-eslint/eslint-plugin')
const _import = require('eslint-plugin-import')

const { fixupPluginRules } = require('@eslint/compat')

const tsParser = require('@typescript-eslint/parser')
const js = require('@eslint/js')

const { FlatCompat } = require('@eslint/eslintrc')

const compat = new FlatCompat({
  baseDirectory: __dirname,
  recommendedConfig: js.configs.recommended,
  allConfig: js.configs.all,
})

module.exports = defineConfig([
  {},
  {
    files: ['**/*.js', '**/*.json'],

    plugins: {
      prettier,
    },

    extends: compat.extends('eslint:recommended', 'prettier'),

    languageOptions: {
      ecmaVersion: 2018,
      parserOptions: {},

      globals: {
        ...globals.node,
      },
    },
  },
  {
    files: ['src/**/*.ts'],

    plugins: {
      '@typescript-eslint': typescriptEslint,
      import: fixupPluginRules(_import),
      prettier,
    },

    languageOptions: {
      parser: tsParser,

      parserOptions: {
        project: './tsconfig.test.json',
      },
    },

    extends: compat.extends(
      'plugin:@typescript-eslint/recommended',
      'plugin:@typescript-eslint/recommended-requiring-type-checking',
      'prettier',
    ),

    rules: {
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-use-before-define': 'off',
      '@typescript-eslint/no-inferrable-types': 'off',

      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
        },
      ],

      '@typescript-eslint/explicit-function-return-type': [
        'error',
        {
          allowExpressions: true,
          allowTypedFunctionExpressions: true,
        },
      ],

      '@typescript-eslint/unbound-method': [
        'error',
        {
          ignoreStatic: true,
        },
      ],
    },
  },
  {
    files: ['**/*.d.ts'],

    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
  {
    files: ['test/**/*.ts'],

    languageOptions: {
      parser: tsParser,

      parserOptions: {
        project: './tsconfig.test.json',
      },
    },

    extends: compat.extends(
      'plugin:@typescript-eslint/recommended',
      'plugin:@typescript-eslint/recommended-requiring-type-checking',
      'prettier',
    ),

    rules: {
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-namespace': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/restrict-plus-operands': 'off',
      '@typescript-eslint/restrict-template-expressions': 'off',
      '@typescript-eslint/unbound-method': 'off',
    },
  },
])
