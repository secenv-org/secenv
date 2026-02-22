/** @type {import('ts-jest').JestConfigWithTsJest} **/
module.exports = {
   preset: "ts-jest/presets/default-esm",
   testEnvironment: "node",
   extensionsToTreatAsEsm: [".ts"],
   moduleNameMapper: {
      "^(\\.{1,2}/.*)\\.js$": "$1",
   },
   resolver: undefined,
   transform: {
      "^.+\\.tsx?$": [
         "ts-jest",
         {
            useESM: true,
            tsconfig: {
               allowJs: true,
               module: "esnext",
               isolatedModules: true,
            },
         },
      ],
   },
   testTimeout: 30000,
   setupFiles: ["<rootDir>/tests/setup.js"],
}
