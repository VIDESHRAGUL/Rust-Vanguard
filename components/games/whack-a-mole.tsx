"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Shield } from "lucide-react"

interface WhackAMoleGameProps {
  isCheatActive: boolean
}

export default function WhackAMoleGame({ isCheatActive }: WhackAMoleGameProps) {
  const [holes, setHoles] = useState<boolean[]>(Array(9).fill(false))
  const [score, setScore] = useState(0)
  const [timeLeft, setTimeLeft] = useState(30)
  const [gameStarted, setGameStarted] = useState(false)
  const [gameOver, setGameOver] = useState(false)
  const [nextMoleIndex, setNextMoleIndex] = useState<number | null>(null)
  const [cheatDetected, setCheatDetected] = useState(false)

  // Initialize the game
  const startGame = () => {
    setHoles(Array(9).fill(false))
    setScore(0)
    setTimeLeft(30)
    setGameStarted(true)
    setGameOver(false)
    setNextMoleIndex(null)
    setCheatDetected(false)
  }

  // Handle whacking a mole
  const whackMole = (index: number) => {
    if (!gameStarted || gameOver || cheatDetected) return

    if (holes[index]) {
      // Hit a mole
      const newHoles = [...holes]
      newHoles[index] = false
      setHoles(newHoles)
      setScore(score + 1)
    }
  }

  // Game timer
  useEffect(() => {
    if (!gameStarted || gameOver) return

    const timer = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          clearInterval(timer)
          setGameOver(true)
          return 0
        }
        return prev - 1
      })
    }, 1000)

    return () => clearInterval(timer)
  }, [gameStarted, gameOver])

  // Spawn moles
  useEffect(() => {
    if (!gameStarted || gameOver) return

    // Calculate next mole position
    const calculateNextMole = () => {
      const emptyHoles = holes.map((hole, index) => (hole ? -1 : index)).filter((index) => index !== -1)

      if (emptyHoles.length > 0) {
        const randomIndex = Math.floor(Math.random() * emptyHoles.length)
        return emptyHoles[randomIndex]
      }
      return null
    }

    // Determine when the next mole will appear (in 1-2 seconds)
    const nextMoleDelay = 1000 + Math.random() * 1000

    // Pre-calculate where the next mole will appear
    const nextIndex = calculateNextMole()
    setNextMoleIndex(nextIndex)

    const spawnTimer = setTimeout(() => {
      if (nextIndex !== null) {
        const newHoles = [...holes]
        newHoles[nextIndex] = true
        setHoles(newHoles)
      }

      // Schedule mole to disappear after 1-2 seconds
      const despawnDelay = 1000 + Math.random() * 1000
      setTimeout(() => {
        if (nextIndex !== null) {
          const newHoles = [...holes]
          newHoles[nextIndex] = false
          setHoles(newHoles)
          setNextMoleIndex(null)
        }
      }, despawnDelay)
    }, nextMoleDelay)

    return () => clearTimeout(spawnTimer)
  }, [holes, gameStarted, gameOver])

  // Apply cheat if active
  useEffect(() => {
    if (isCheatActive && gameStarted && !gameOver) {
      // Code injection cheat: Show where moles will appear before they do

      // Check if anti-cheat is active in the parent component
      const antiCheatActive = document.querySelector('[data-anticheat="active"]') !== null

      if (antiCheatActive) {
        // Anti-cheat detected the code injection attempt
        setCheatDetected(true)
      }
    }
  }, [isCheatActive, gameStarted, nextMoleIndex])

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <div className="mb-4 flex justify-between w-full max-w-md">
        <div className="text-green-500">Score: {score}</div>
        <div className="text-yellow-500">Time: {timeLeft}s</div>
      </div>

      {cheatDetected ? (
        <div className="text-center space-y-4">
          <Shield className="h-16 w-16 text-red-500 mx-auto" />
          <h3 className="text-xl font-bold text-red-500">Code Injection Detected!</h3>
          <p className="max-w-md mx-auto text-gray-400">
            The anti-cheat system has detected an attempt to inject unauthorized code. This type of cheat tries to
            reveal future mole positions by accessing internal game state.
          </p>
          <Button variant="destructive" onClick={startGame}>
            Restart Game
          </Button>
        </div>
      ) : gameStarted ? (
        <div className="grid grid-cols-3 gap-3 bg-gray-800 p-4 rounded-md">
          {holes.map((hasMole, index) => (
            <div
              key={index}
              className={`w-20 h-20 rounded-full flex items-center justify-center cursor-pointer
                ${hasMole ? "bg-brown-600" : "bg-green-800"}
                ${isCheatActive && document.querySelector('[data-anticheat="active"]') === null && nextMoleIndex === index && !hasMole ? "bg-yellow-900/30" : ""}
                transition-colors duration-200`}
              onClick={() => whackMole(index)}
            >
              {hasMole && (
                <div className="w-16 h-16 bg-brown-500 rounded-full flex items-center justify-center">
                  <div className="w-12 h-8 bg-brown-400 rounded-full flex items-center justify-center">
                    <div className="flex space-x-4">
                      <div className="w-2 h-2 bg-black rounded-full"></div>
                      <div className="w-2 h-2 bg-black rounded-full"></div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        <Button onClick={startGame} className="bg-green-600 hover:bg-green-700">
          Start Game
        </Button>
      )}

      {gameOver && !cheatDetected && (
        <div className="mt-4 text-center">
          <p className="text-xl mb-2">Game Over! Final score: {score}</p>
          <Button onClick={startGame} className="bg-green-600 hover:bg-green-700">
            Play Again
          </Button>
        </div>
      )}

      {isCheatActive && gameStarted && !cheatDetected && (
        <div className="mt-4 text-yellow-500 text-sm">Code Injection Cheat Active: Revealing future mole positions</div>
      )}

      <div className="mt-6 bg-gray-800 p-4 rounded-md max-w-md">
        <h3 className="font-bold text-lg mb-2">How This Cheat Works:</h3>
        <p className="text-sm text-gray-300 mb-3">
          The Code Injection cheat modifies the game's code to reveal where moles will appear before they do. It
          accesses internal variables that store future mole positions, giving the player an unfair advantage.
        </p>

        <h3 className="font-bold text-lg mb-2">How Anti-Cheat Blocks It:</h3>
        <p className="text-sm text-gray-300">
          The anti-cheat system continuously monitors the integrity of the game code. When it detects unauthorized
          modifications or access to protected variables, it immediately terminates the game and flags the session as
          compromised.
        </p>
      </div>
    </div>
  )
}

