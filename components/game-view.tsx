"use client"

import { useEffect } from "react"
import type { Game } from "@/lib/types"
import MemoryMatchGame from "@/components/games/memory-match"
import MinesweeperGame from "@/components/games/minesweeper"
import NumberGuessGame from "@/components/games/number-guess"
import SpaceShooterGame from "@/components/games/space-shooter"
import PuzzleSlideGame from "@/components/games/puzzle-slide"
import TicTacToeGame from "@/components/games/tic-tac-toe"

interface GameViewProps {
  game: Game
  isCheatActive: boolean
  isAntiCheatActive: boolean
}

export default function GameView({ game, isCheatActive, isAntiCheatActive }: GameViewProps) {
  // Set global anti-cheat state for games to access
  useEffect(() => {
    window.isAntiCheatActive = isAntiCheatActive
  }, [isAntiCheatActive])

  // Render the appropriate game component based on the selected game
  switch (game.id) {
    case "memory-match":
      return <MemoryMatchGame isCheatActive={isCheatActive} />
    case "minesweeper":
      return <MinesweeperGame isCheatActive={isCheatActive} />
    case "number-guess":
      return <NumberGuessGame isCheatActive={isCheatActive} />
    case "space-shooter":
      return <SpaceShooterGame isCheatActive={isCheatActive} />
    case "puzzle-slide":
      return <PuzzleSlideGame isCheatActive={isCheatActive} />
    case "tic-tac-toe":
      return <TicTacToeGame isCheatActive={isCheatActive} />
    default:
      return (
        <div className="flex items-center justify-center h-full">
          <p>Game not implemented yet</p>
        </div>
      )
  }
}

