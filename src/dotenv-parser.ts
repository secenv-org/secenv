// lenient parser for migrate command
import * as fs from "fs"
import { safeReadFile } from "./filesystem.js"

export interface DotenvLine {
   key: string
   value: string
   lineNumber: number
}

export function parseDotenvFallback(filePath: string): DotenvLine[] {
   if (!fs.existsSync(filePath)) {
      return []
   }

   let content = safeReadFile(filePath)
   if (content.startsWith("\uFEFF")) {
      content = content.slice(1)
   }

   // Handle both CR LF and LF
   const lines = content.split(/\r?\n/)
   const parsedLines: DotenvLine[] = []

   for (let i = 0; i < lines.length; i++) {
      const lineNumber = i + 1
      let raw = lines[i]
      let trimmed = raw.trim()

      if (!trimmed || trimmed.startsWith("#")) {
         continue
      }

      // Strip "export " prefix if present
      const exportRegex = /^export\s+/
      if (exportRegex.test(trimmed)) {
         trimmed = trimmed.replace(exportRegex, "")
      }

      const eqIndex = trimmed.indexOf("=")
      if (eqIndex === -1) {
         continue // Skip invalid lines
      }

      const key = trimmed.slice(0, eqIndex).trim()
      let value = trimmed.slice(eqIndex + 1).trim()

      // Inline comments removal (simplistic, just look for # with preceding spaces)
      // This might strip valid # inside quotes, but fine for migration fallback
      const commentIndex = value.indexOf(" #")
      if (commentIndex !== -1) {
         value = value.slice(0, commentIndex).trim()
      }

      // Handle quotes
      if (value.startsWith('"') && value.endsWith('"')) {
         value = value.slice(1, -1)
         // rudimentary unescape
         value = value.replace(/\\n/g, "\n").replace(/\\"/g, '"')
      } else if (value.startsWith("'") && value.endsWith("'")) {
         value = value.slice(1, -1)
      }

      parsedLines.push({
         key,
         value,
         lineNumber,
      })
   }

   return parsedLines
}
