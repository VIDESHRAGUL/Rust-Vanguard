export interface Game {
  id: string
  title: string
  description: string
  image: string
  cheatType: string
  antiCheatType: string
}

// Add global window type for anti-cheat state
declare global {
  interface Window {
    isAntiCheatActive: boolean
  }
}

