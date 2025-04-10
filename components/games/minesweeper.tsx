"use client"

import type React from "react"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"

interface MinesweeperGameProps {
  isCheatActive: boolean
}

export default function MinesweeperGame({ isCheatActive }: MinesweeperGameProps) {
  const [board, setBoard] = useState<number[][]>([])
  const [revealed, setRevealed] = useState<boolean[][]>([])
  const [flagged, setFlagged] = useState<boolean[][]>([])
  const [gameOver, setGameOver] = useState(false)
  const [gameWon, setGameWon] = useState(false)
  const [gameStarted, setGameStarted] = useState(false)
  const [mineCount, setMineCount] = useState(10)
  const [flagsUsed, setFlagsUsed] = useState(0)

  const rows = 8
  const cols = 8

  // Initialize the game
  const initializeGame = () => {
    // Create empty board
    const newBoard = Array(rows)
      .fill(null)
      .map(() => Array(cols).fill(0))
    const newRevealed = Array(rows)
      .fill(null)
      .map(() => Array(cols).fill(false))
    const newFlagged = Array(rows)
      .fill(null)
      .map(() => Array(cols).fill(false))

    // Place mines
    let minesPlaced = 0
    while (minesPlaced < mineCount) {
      const row = Math.floor(Math.random() * rows)
      const col = Math.floor(Math.random() * cols)

      if (newBoard[row][col] !== -1) {
        newBoard[row][col] = -1
        minesPlaced++
      }
    }

    // Calculate numbers
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        if (newBoard[r][c] === -1) continue

        let count = 0
        // Check all 8 surrounding cells
        for (let dr = -1; dr <= 1; dr++) {
          for (let dc = -1; dc <= 1; dc++) {
            const nr = r + dr
            const nc = c + dc

            if (nr >= 0 && nr < rows && nc >= 0 && nc < cols && newBoard[nr][nc] === -1) {
              count++
            }
          }
        }

        newBoard[r][c] = count
      }
    }

    setBoard(newBoard)
    setRevealed(newRevealed)
    setFlagged(newFlagged)
    setGameOver(false)
    setGameWon(false)
    setFlagsUsed(0)
    setGameStarted(true)
  }

  // Reveal a cell
  const revealCell = (r: number, c: number) => {
    if (gameOver || gameWon || revealed[r][c] || flagged[r][c]) return

    const newRevealed = [...revealed.map((row) => [...row])]

    // If it's a mine, game over
    if (board[r][c] === -1) {
      newRevealed[r][c] = true
      setRevealed(newRevealed)
      setGameOver(true)
      return
    }

    // Reveal the cell
    revealCellRecursive(newRevealed, r, c)
    setRevealed(newRevealed)

    // Check if game is won
    checkWinCondition(newRevealed)
  }

  // Recursively reveal cells (for empty cells)
  const revealCellRecursive = (newRevealed: boolean[][], r: number, c: number) => {
    if (r < 0 || r >= rows || c < 0 || c >= cols || newRevealed[r][c] || flagged[r][c]) return

    newRevealed[r][c] = true

    // If it's an empty cell, reveal neighbors
    if (board[r][c] === 0) {
      for (let dr = -1; dr <= 1; dr++) {
        for (let dc = -1; dc <= 1; dc++) {
          revealCellRecursive(newRevealed, r + dr, c + dc)
        }
      }
    }
  }

  // Toggle flag on a cell
  const toggleFlag = (r: number, c: number, e: React.MouseEvent) => {
    e.preventDefault()

    if (gameOver || gameWon || revealed[r][c]) return

    const newFlagged = [...flagged.map((row) => [...row])]

    if (newFlagged[r][c]) {
      newFlagged[r][c] = false
      setFlagsUsed(flagsUsed - 1)
    } else if (flagsUsed < mineCount) {
      newFlagged[r][c] = true
      setFlagsUsed(flagsUsed + 1)
    }

    setFlagged(newFlagged)

    // Check if all mines are flagged correctly
    checkWinCondition(revealed, newFlagged)
  }

  // Check if the game is won
  const checkWinCondition = (currentRevealed: boolean[][], currentFlagged = flagged) => {
    // Win if all non-mine cells are revealed
    let allNonMinesRevealed = true

    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        if (board[r][c] !== -1 && !currentRevealed[r][c]) {
          allNonMinesRevealed = false
          break
        }
      }
      if (!allNonMinesRevealed) break
    }

    // Win if all mines are correctly flagged
    let allMinesFlagged = true
    let correctFlags = 0

    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        if (board[r][c] === -1 && !currentFlagged[r][c]) {
          allMinesFlagged = false
        }
        if (board[r][c] === -1 && currentFlagged[r][c]) {
          correctFlags++
        }
      }
    }

    if ((allNonMinesRevealed || (allMinesFlagged && correctFlags === mineCount)) && !gameOver) {
      setGameWon(true)
    }
  }

  // Apply cheat: Reveal mine locations
  useEffect(() => {
    if (isCheatActive && gameStarted && !gameOver && !gameWon) {
      // Memory injection cheat: Reveal mine locations without triggering them
      const newRevealed = [...revealed.map((row) => [...row])]
      const newFlagged = [...flagged.map((row) => [...row])]

      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          if (board[r][c] === -1 && !flagged[r][c]) {
            newFlagged[r][c] = true
            setFlagsUsed((prev) => prev + 1)
          }
        }
      }

      setFlagged(newFlagged)
      checkWinCondition(newRevealed, newFlagged)
    }
  }, [isCheatActive, gameStarted])

  // Get cell color based on number
  const getCellColor = (value: number) => {
    switch (value) {
      case 1:
        return "text-blue-500"
      case 2:
        return "text-green-500"
      case 3:
        return "text-red-500"
      case 4:
        return "text-purple-500"
      case 5:
        return "text-yellow-500"
      case 6:
        return "text-pink-500"
      case 7:
        return "text-orange-500"
      case 8:
        return "text-gray-500"
      default:
        return ""
    }
  }

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <div className="mb-4 flex justify-between w-full max-w-md">
        <div className="text-yellow-500">Mines: {mineCount}</div>
        <div className="text-green-500">
          Flags: {flagsUsed}/{mineCount}
        </div>
      </div>

      {gameStarted ? (
        <div className="grid gap-1 bg-gray-800 p-2 rounded-md">
          {board.map((row, r) => (
            <div key={r} className="flex gap-1">
              {row.map((cell, c) => (
                <button
                  key={`${r}-${c}`}
                  className={`w-8 h-8 flex items-center justify-center font-bold text-sm
                    ${revealed[r][c] ? (cell === -1 ? "bg-red-600" : "bg-gray-700") : "bg-gray-600 hover:bg-gray-500"}
                    ${flagged[r][c] ? "bg-yellow-600" : ""}
                    ${getCellColor(cell)}`}
                  onClick={() => revealCell(r, c)}
                  onContextMenu={(e) => toggleFlag(r, c, e)}
                  disabled={gameOver || gameWon}
                >
                  {revealed[r][c] ? (cell === -1 ? "💣" : cell > 0 ? cell : "") : flagged[r][c] ? "🚩" : ""}
                </button>
              ))}
            </div>
          ))}
        </div>
      ) : (
        <Button onClick={initializeGame} className="bg-green-600 hover:bg-green-700">
          Start Game
        </Button>
      )}

      {(gameOver || gameWon) && (
        <div className="mt-4">
          <div className={`text-center mb-2 ${gameWon ? "text-green-500" : "text-red-500"}`}>
            {gameWon ? "You Win!" : "Game Over!"}
          </div>
          <Button onClick={initializeGame} className="bg-green-600 hover:bg-green-700">
            Play Again
          </Button>
        </div>
      )}

      {isCheatActive && gameStarted && (
        <div className="mt-4 text-yellow-500 text-sm">Memory Injection Cheat Active: Mine locations revealed</div>
      )}
    </div>
  )
}

