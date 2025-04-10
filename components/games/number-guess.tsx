"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

interface NumberGuessGameProps {
  isCheatActive: boolean
}

export default function NumberGuessGame({ isCheatActive }: NumberGuessGameProps) {
  const [targetNumber, setTargetNumber] = useState<number>(0)
  const [guess, setGuess] = useState<string>("")
  const [message, setMessage] = useState<string>("")
  const [attempts, setAttempts] = useState<number>(0)
  const [gameOver, setGameOver] = useState<boolean>(false)
  const [gameStarted, setGameStarted] = useState<boolean>(false)
  const [history, setHistory] = useState<{ guess: number; result: string }[]>([])
  const maxAttempts = 10

  // Initialize the game
  const startGame = () => {
    const newTarget = Math.floor(Math.random() * 100) + 1
    setTargetNumber(newTarget)
    setGuess("")
    setMessage("I'm thinking of a number between 1 and 100.")
    setAttempts(0)
    setGameOver(false)
    setGameStarted(true)
    setHistory([])

    console.log("Target number:", newTarget) // For debugging
  }

  // Handle guess submission
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!gameStarted || gameOver) return

    const guessNumber = Number.parseInt(guess)

    if (isNaN(guessNumber) || guessNumber < 1 || guessNumber > 100) {
      setMessage("Please enter a valid number between 1 and 100.")
      return
    }

    const newAttempts = attempts + 1
    setAttempts(newAttempts)

    let result = ""
    if (guessNumber === targetNumber) {
      result = "correct"
      setMessage(`Congratulations! You guessed the number in ${newAttempts} attempts.`)
      setGameOver(true)
    } else if (newAttempts >= maxAttempts) {
      result = "out of attempts"
      setMessage(`Game over! The number was ${targetNumber}. You've used all ${maxAttempts} attempts.`)
      setGameOver(true)
    } else if (guessNumber < targetNumber) {
      result = "too low"
      setMessage(`Too low! Try a higher number. Attempts: ${newAttempts}/${maxAttempts}`)
    } else {
      result = "too high"
      setMessage(`Too high! Try a lower number. Attempts: ${newAttempts}/${maxAttempts}`)
    }

    setHistory([...history, { guess: guessNumber, result }])
    setGuess("")
  }

  // Apply cheat if active
  useEffect(() => {
    if (isCheatActive && gameStarted && !gameOver) {
      // API Manipulation cheat: Reveal the target number
      setMessage(`Cheat active! The target number is ${targetNumber}. Attempts: ${attempts}/${maxAttempts}`)
    } else if (gameStarted && !gameOver) {
      setMessage(`I'm thinking of a number between 1 and 100. Attempts: ${attempts}/${maxAttempts}`)
    }
  }, [isCheatActive, gameStarted, gameOver, targetNumber, attempts])

  return (
    <div className="flex flex-col items-center justify-center h-full max-w-md mx-auto">
      <h3 className="text-xl font-bold mb-4">Number Guessing Game</h3>

      {!gameStarted ? (
        <Button onClick={startGame} className="bg-green-600 hover:bg-green-700">
          Start Game
        </Button>
      ) : (
        <div className="w-full space-y-4">
          <div
            className={`text-center p-3 rounded-md ${gameOver ? (message.includes("Congratulations") ? "bg-green-900/50" : "bg-red-900/50") : "bg-gray-800"}`}
          >
            {message}
          </div>

          <form onSubmit={handleSubmit} className="flex gap-2">
            <Input
              type="number"
              min="1"
              max="100"
              value={guess}
              onChange={(e) => setGuess(e.target.value)}
              placeholder="Enter your guess"
              disabled={gameOver}
              className="bg-gray-700 border-gray-600"
            />
            <Button type="submit" disabled={gameOver || !guess} className="bg-green-600 hover:bg-green-700">
              Guess
            </Button>
          </form>

          {history.length > 0 && (
            <div className="mt-4">
              <h4 className="text-sm font-medium mb-2">Guess History:</h4>
              <div className="bg-gray-800 rounded-md p-2 max-h-40 overflow-y-auto">
                {history.map((entry, index) => (
                  <div key={index} className="flex justify-between text-sm py-1 border-b border-gray-700 last:border-0">
                    <span>
                      Guess #{index + 1}: {entry.guess}
                    </span>
                    <span
                      className={
                        entry.result === "correct"
                          ? "text-green-500"
                          : entry.result === "too high"
                            ? "text-red-500"
                            : entry.result === "too low"
                              ? "text-blue-500"
                              : "text-gray-500"
                      }
                    >
                      {entry.result}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {gameOver && (
            <Button onClick={startGame} className="w-full bg-green-600 hover:bg-green-700">
              Play Again
            </Button>
          )}

          {isCheatActive && (
            <div className="text-yellow-500 text-sm text-center">
              API Manipulation Cheat Active: Target number revealed
            </div>
          )}
        </div>
      )}
    </div>
  )
}

