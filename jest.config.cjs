module.exports = {
   testEnvironment: "node",
   extensionsToTreatAsEsm: [".ts"],
   moduleNameMapper: {
      "^(\\.{1,2}/.*)\\.js$": "$1",
   },
   transform: {
      "^.+\\.tsx?$": [
         "@swc/jest",
         {
            jsc: {
               target: "es2022",
               parser: { syntax: "typescript" },
            },
            module: { type: "es6" },
         },
      ],
   },
   testTimeout: 30000,
   testPathIgnorePatterns: ["/node_modules/", "/tests/deno/", "/tests/bun/"],
}
