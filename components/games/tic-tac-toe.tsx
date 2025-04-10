"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"

interface TicTacToeGameProps {
  isCheatActive: boolean
}

export default function TicTacToeGame({ isCheatActive }: TicTacToeGameProps) {
  const [board, setBoard] = useState<string[]>(Array(9).fill(""))
  const [isXNext, setIsXNext] = useState(true)
  const [winner, setWinner] = useState<string | null>(null)
  const [gameStarted, setGameStarted] = useState(false)
  const [aiThinking, setAiThinking] = useState(false)

  // Start a new game
  const startGame = () => {
    setBoard(Array(9).fill(""))
    setIsXNext(true)
    setWinner(null)
    setGameStarted(true)
  }

  // Handle player move
  const handleClick = (index: number) => {
    if (winner || board[index] || !isXNext || aiThinking) return

    const newBoard = [...board]
    newBoard[index] = "X"
    setBoard(newBoard)
    setIsXNext(false)
  }

  // Check for winner
  const calculateWinner = (squares: string[]): string | null => {
    const lines = [
      [0, 1, 2],
      [3, 4, 5],
      [6, 7, 8],
      [0, 3, 6],
      [1, 4, 7],
      [2, 5, 8],
      [0, 4, 8],
      [2, 4, 6],
    ]

    for (let i = 0; i < lines.length; i++) {
      const [a, b, c] = lines[i]
      if (squares[a] && squares[a] === squares[b] && squares[a] === squares[c]) {
        return squares[a]
      }
    }

    // Check for draw
    if (squares.every((square) => square !== "")) {
      return "draw"
    }

    return null
  }

  // AI move
  const aiMove = () => {
    if (winner || board.every((square) => square !== "")) return

    setAiThinking(true)

    setTimeout(() => {
      const newBoard = [...board]

      if (isCheatActive) {
        // Logic manipulation cheat: AI makes a bad move
        const emptySquares = board.map((square, index) => (square === "" ? index : -1)).filter((index) => index !== -1)
        if (emptySquares.length > 0) {
          // Make a random move instead of the best move
          const randomIndex = Math.floor(Math.random() * emptySquares.length)
          newBoard[emptySquares[randomIndex]] = "O"
        }
      } else {
        // Normal AI: Make the best move using minimax
        const bestMove = findBestMove(newBoard)
        if (bestMove !== -1) {
          newBoard[bestMove] = "O"
        }
      }

      setBoard(newBoard)
      setIsXNext(true)
      setAiThinking(false)
    }, 500)
  }

  // Minimax algorithm for AI
  const minimax = (board: string[], depth: number, isMaximizing: boolean): number => {
    const result = calculateWinner(board)

    if (result === "X") return -10 + depth
    if (result === "O") return 10 - depth
    if (result === "draw") return 0

    if (isMaximizing) {
      let bestScore = Number.NEGATIVE_INFINITY
      for (let i = 0; i < board.length; i++) {
        if (board[i] === "") {
          board[i] = "O"
          const score = minimax(board, depth + 1, false)
          board[i] = ""
          bestScore = Math.max(score, bestScore)
        }
      }
      return bestScore
    } else {
      let bestScore = Number.POSITIVE_INFINITY
      for (let i = 0; i < board.length; i++) {
        if (board[i] === "") {
          board[i] = "X"
          const score = minimax(board, depth + 1, true)
          board[i] = ""
          bestScore = Math.min(score, bestScore)
        }
      }
      return bestScore
    }
  }

  // Find the best move for AI
  const findBestMove = (board: string[]): number => {
    let bestScore = Number.NEGATIVE_INFINITY
    let bestMove = -1

    for (let i = 0; i < board.length; i++) {
      if (board[i] === "") {
        board[i] = "O"
        const score = minimax(board, 0, false)
        board[i] = ""

        if (score > bestScore) {
          bestScore = score
          bestMove = i
        }
      }
    }

    return bestMove
  }

  // AI's turn
  useEffect(() => {
    if (gameStarted && !isXNext && !winner) {
      aiMove()
    }
  }, [isXNext, gameStarted])

  // Check for winner after each move
  useEffect(() => {
    const result = calculateWinner(board)
    if (result) {
      setWinner(result)
    }
  }, [board])

  // Render a square
  const renderSquare = (index: number) => {
    return (
      <button
        className={`w-20 h-20 text-3xl font-bold flex items-center justify-center
          ${board[index] ? "cursor-default" : "cursor-pointer"}
          ${board[index] === "X" ? "text-blue-500" : "text-red-500"}
          bg-gray-800 border border-gray-700 hover:bg-gray-700`}
        onClick={() => handleClick(index)}
        disabled={!!winner || !!board[index] || !isXNext || aiThinking}
      >
        {board[index]}
      </button>
    )
  }

  return (
    <div className="flex flex-col items-center justify-center h-full">
      {gameStarted ? (
        <>
          <div className="mb-4">
            {winner ? (
              <div className="text-center">
                {winner === "draw" ? (
                  <p className="text-yellow-500 text-xl">It's a draw!</p>
                ) : (
                  <p className={`text-xl ${winner === "X" ? "text-blue-500" : "text-red-500"}`}>
                    {winner === "X" ? "You win!" : "AI wins!"}
                  </p>
                )}
              </div>
            ) : (
              <p className={`text-xl ${isXNext ? "text-blue-500" : "text-red-500"}`}>
                {isXNext ? "Your turn (X)" : "AI thinking..."}
              </p>
            )}
          </div>

          <div className="grid grid-cols-3 gap-1">
            {renderSquare(0)}
            {renderSquare(1)}
            {renderSquare(2)}
            {renderSquare(3)}
            {renderSquare(4)}
            {renderSquare(5)}
            {renderSquare(6)}
            {renderSquare(7)}
            {renderSquare(8)}
          </div>

          {winner && (
            <Button onClick={startGame} className="mt-4 bg-green-600 hover:bg-green-700">
              Play Again
            </Button>
          )}

          {isCheatActive && (
            <div className="mt-4 text-yellow-500 text-sm">
              Logic Manipulation Cheat Active: AI makes suboptimal moves
            </div>
          )}
        </>
      ) : (
        <div className="text-center">
          <h3 className="text-xl font-bold mb-4">Tic Tac Toe</h3>
          <p className="mb-4 text-gray-400">Play against the AI. You are X, AI is O.</p>
          <Button onClick={startGame} className="bg-green-600 hover:bg-green-700">
            Start Game
          </Button>
        </div>
      )}
    </div>
  )
}

