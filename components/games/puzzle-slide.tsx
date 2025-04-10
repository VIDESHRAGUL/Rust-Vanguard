"use client"

import { useEffect, useState, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Shield } from "lucide-react"

interface PuzzleSlideGameProps {
  isCheatActive: boolean
}

export default function PuzzleSlideGame({ isCheatActive }: PuzzleSlideGameProps) {
  const [board, setBoard] = useState<number[][]>([])
  const [moves, setMoves] = useState(0)
  const [gameStarted, setGameStarted] = useState(false)
  const [gameWon, setGameWon] = useState(false)
  const [emptyCell, setEmptyCell] = useState<{ row: number; col: number }>({ row: 3, col: 3 })
  const [cheatDetected, setCheatDetected] = useState(false)
  const [solutionPath, setSolutionPath] = useState<{ row: number; col: number }[]>([])

  // Anti-cheat reference
  const codeIntegrityRef = useRef<string>("original")

  // Initialize the game
  const initializeGame = () => {
    // Create a solved 4x4 puzzle
    const solved = [
      [1, 2, 3, 4],
      [5, 6, 7, 8],
      [9, 10, 11, 12],
      [13, 14, 15, 0], // 0 represents the empty cell
    ]

    // Shuffle the puzzle (make random valid moves)
    const shuffled = JSON.parse(JSON.stringify(solved))
    let emptyPos = { row: 3, col: 3 }

    // Make 100 random valid moves to shuffle
    for (let i = 0; i < 100; i++) {
      const possibleMoves = getPossibleMoves(emptyPos.row, emptyPos.col)
      if (possibleMoves.length > 0) {
        const randomMove = possibleMoves[Math.floor(Math.random() * possibleMoves.length)]
        shuffled[emptyPos.row][emptyPos.col] = shuffled[randomMove.row][randomMove.col]
        shuffled[randomMove.row][randomMove.col] = 0
        emptyPos = { row: randomMove.row, col: randomMove.col }
      }
    }

    setBoard(shuffled)
    setEmptyCell(emptyPos)
    setMoves(0)
    setGameStarted(true)
    setGameWon(false)
    setCheatDetected(false)
    setSolutionPath([])

    // Reset code integrity for anti-cheat
    codeIntegrityRef.current = "original"
  }

  // Get possible moves for the empty cell
  const getPossibleMoves = (row: number, col: number) => {
    const moves = []

    // Check up
    if (row > 0) moves.push({ row: row - 1, col })
    // Check down
    if (row < 3) moves.push({ row: row + 1, col })
    // Check left
    if (col > 0) moves.push({ row, col: col - 1 })
    // Check right
    if (col < 3) moves.push({ row, col: col + 1 })

    return moves
  }

  // Handle tile click
  const handleTileClick = (row: number, col: number) => {
    if (!gameStarted || gameWon || cheatDetected) return

    // Check if the clicked tile is adjacent to the empty cell
    const possibleMoves = getPossibleMoves(emptyCell.row, emptyCell.col)
    const isValidMove = possibleMoves.some((move) => move.row === row && move.col === col)

    if (isValidMove) {
      // Make the move
      const newBoard = JSON.parse(JSON.stringify(board))
      newBoard[emptyCell.row][emptyCell.col] = newBoard[row][col]
      newBoard[row][col] = 0

      setBoard(newBoard)
      setEmptyCell({ row, col })
      setMoves(moves + 1)

      // Check if puzzle is solved
      checkWinCondition(newBoard)
    }
  }

  // Check if the puzzle is solved
  const checkWinCondition = (currentBoard: number[][]) => {
    // The solved state has numbers in order from 1-15 with 0 in the bottom right
    let isSolved = true
    let expected = 1

    for (let row = 0; row < 4; row++) {
      for (let col = 0; col < 4; col++) {
        // Skip the last cell which should be 0
        if (row === 3 && col === 3) {
          if (currentBoard[row][col] !== 0) {
            isSolved = false
          }
          break
        }

        if (currentBoard[row][col] !== expected) {
          isSolved = false
          break
        }

        expected++
      }

      if (!isSolved) break
    }

    if (isSolved) {
      setGameWon(true)
    }
  }

  // Apply cheat if active
  useEffect(() => {
    if (isCheatActive && gameStarted && !gameWon) {
      try {
        // Code Injection Cheat: Inject code to show solution path
        const injectedCode = "injected"

        // Anti-cheat detection
        if (isAntiCheatActive) {
          // Check if code has been modified (in a real system, this would be more sophisticated)
          if (codeIntegrityRef.current !== "original") {
            console.log("Anti-cheat: Code injection detected!")
            setCheatDetected(true)
            return
          }
        }

        // If anti-cheat is not active or didn't detect the cheat, show solution path
        if (!isAntiCheatActive) {
          // Simulate code injection by modifying the code integrity
          codeIntegrityRef.current = injectedCode

          // Generate a fake solution path for demonstration
          const fakePath = []
          const possibleMoves = getPossibleMoves(emptyCell.row, emptyCell.col)

          // Add 5 steps to the solution path
          let currentPos = { ...emptyCell }
          for (let i = 0; i < 5; i++) {
            const validMoves = getPossibleMoves(currentPos.row, currentPos.col).filter(
              (move) => board[move.row][move.col] !== 0,
            )

            if (validMoves.length > 0) {
              const nextMove = validMoves[Math.floor(Math.random() * validMoves.length)]
              fakePath.push(nextMove)
              currentPos = nextMove
            }
          }

          setSolutionPath(fakePath)
        }
      } catch (error) {
        console.error("Cheat error:", error)
      }
    } else {
      setSolutionPath([])
    }
  }, [isCheatActive, gameStarted, gameWon, board, emptyCell])

  // Anti-cheat active state
  const isAntiCheatActive = gameStarted && !gameWon && window.isAntiCheatActive

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <div className="mb-4 flex justify-between w-full max-w-md">
        <div className="text-blue-500">Moves: {moves}</div>
        {isAntiCheatActive && (
          <div className="flex items-center text-green-500">
            <Shield className="h-4 w-4 mr-1" />
            Anti-Cheat Active
          </div>
        )}
      </div>

      {cheatDetected ? (
        <div className="text-center space-y-4 p-6 bg-red-900/20 rounded-lg">
          <h3 className="text-xl font-bold text-red-500">Code Injection Detected!</h3>
          <p className="text-gray-300">
            The anti-cheat system has detected an attempt to inject unauthorized code into the game.
          </p>
          <Button onClick={initializeGame} className="bg-green-600 hover:bg-green-700">
            Restart Game
          </Button>
        </div>
      ) : gameStarted ? (
        <div className="grid grid-cols-4 gap-1 bg-gray-800 p-2 rounded-md">
          {board.map((row, rowIndex) =>
            row.map((tile, colIndex) => {
              const isEmptyCell = tile === 0
              const isPartOfSolution = solutionPath.some((pos) => pos.row === rowIndex && pos.col === colIndex)

              return (
                <button
                  key={`${rowIndex}-${colIndex}`}
                  className={`w-16 h-16 flex items-center justify-center font-bold text-lg
                    ${isEmptyCell ? "bg-gray-800" : "bg-gray-700 hover:bg-gray-600"}
                    ${isPartOfSolution ? "bg-yellow-600 border-2 border-yellow-400" : ""}
                    rounded-md transition-colors`}
                  onClick={() => handleTileClick(rowIndex, colIndex)}
                  disabled={isEmptyCell || gameWon}
                >
                  {!isEmptyCell && tile}
                </button>
              )
            }),
          )}
        </div>
      ) : (
        <Button onClick={initializeGame} className="bg-green-600 hover:bg-green-700">
          Start Game
        </Button>
      )}

      {gameWon && (
        <div className="mt-4 text-center">
          <p className="text-green-500 mb-2">Congratulations! You solved the puzzle in {moves} moves.</p>
          <Button onClick={initializeGame} className="bg-green-600 hover:bg-green-700">
            Play Again
          </Button>
        </div>
      )}

      {isCheatActive && gameStarted && !gameWon && !cheatDetected && (
        <div className="mt-4 text-yellow-500 text-sm">
          Code Injection Cheat Active: Showing solution path by injecting unauthorized code
        </div>
      )}

      <div className="mt-6 p-4 bg-gray-800/50 rounded-lg max-w-md">
        <h3 className="text-lg font-semibold mb-2">How the Cheat Works:</h3>
        <p className="text-sm text-gray-300 mb-3">
          The Code Injection cheat works by inserting unauthorized code into the game's memory. This injected code
          reveals the solution path by highlighting which tiles to move to solve the puzzle.
        </p>

        <h3 className="text-lg font-semibold mb-2">How Anti-Cheat Blocks It:</h3>
        <p className="text-sm text-gray-300">
          The Code Integrity Checking anti-cheat system continuously monitors the game's code and calculates checksums
          to verify that no unauthorized modifications have been made. When it detects injected code, it immediately
          terminates the cheat attempt and protects the game's integrity.
        </p>
      </div>
    </div>
  )
}

