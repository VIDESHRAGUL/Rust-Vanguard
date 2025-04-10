"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Shield } from "lucide-react"

interface MemoryCardGameProps {
  isCheatActive: boolean
}

export default function MemoryCardGame({ isCheatActive }: MemoryCardGameProps) {
  const [cards, setCards] = useState<number[]>([])
  const [flipped, setFlipped] = useState<boolean[]>([])
  const [matched, setMatched] = useState<boolean[]>([])
  const [moves, setMoves] = useState(0)
  const [firstCard, setFirstCard] = useState<number | null>(null)
  const [secondCard, setSecondCard] = useState<number | null>(null)
  const [gameStarted, setGameStarted] = useState(false)
  const [gameOver, setGameOver] = useState(false)
  const [cheatDetected, setCheatDetected] = useState(false)

  // Initialize the game
  const initializeGame = () => {
    // Create pairs of cards (8 pairs = 16 cards)
    const cardValues = Array.from({ length: 8 }, (_, i) => i + 1)
    const cardPairs = [...cardValues, ...cardValues]

    // Shuffle the cards
    const shuffled = cardPairs.sort(() => Math.random() - 0.5)

    setCards(shuffled)
    setFlipped(Array(16).fill(false))
    setMatched(Array(16).fill(false))
    setMoves(0)
    setFirstCard(null)
    setSecondCard(null)
    setGameStarted(true)
    setGameOver(false)
    setCheatDetected(false)
  }

  // Handle card click
  const handleCardClick = (index: number) => {
    // Prevent clicking if game is over or card is already flipped/matched
    if (gameOver || flipped[index] || matched[index] || cheatDetected) return

    // Prevent flipping more than 2 cards at once
    if (firstCard !== null && secondCard !== null) return

    // Flip the card
    const newFlipped = [...flipped]
    newFlipped[index] = true
    setFlipped(newFlipped)

    // Set first or second card
    if (firstCard === null) {
      setFirstCard(index)
    } else {
      setSecondCard(index)
      setMoves(moves + 1)
    }
  }

  // Check for matches
  useEffect(() => {
    if (firstCard === null || secondCard === null) return

    // Check if cards match
    if (cards[firstCard] === cards[secondCard]) {
      // Cards match
      const newMatched = [...matched]
      newMatched[firstCard] = true
      newMatched[secondCard] = true
      setMatched(newMatched)

      // Reset selected cards
      setFirstCard(null)
      setSecondCard(null)

      // Check if game is over
      if (newMatched.every((m) => m)) {
        setGameOver(true)
      }
    } else {
      // Cards don't match, flip them back after a delay
      setTimeout(() => {
        const newFlipped = [...flipped]
        newFlipped[firstCard] = false
        newFlipped[secondCard] = false
        setFlipped(newFlipped)

        // Reset selected cards
        setFirstCard(null)
        setSecondCard(null)
      }, 1000)
    }
  }, [firstCard, secondCard])

  // Apply cheat if active
  useEffect(() => {
    if (isCheatActive && gameStarted && !gameOver) {
      // Buffer overflow cheat: Access memory beyond the allocated array
      // In a real game, this would be exploiting a vulnerability to see card values
      // Here we simulate it by revealing all cards temporarily

      // Check if anti-cheat is active in the parent component
      const antiCheatActive = document.querySelector('[data-anticheat="active"]') !== null

      if (antiCheatActive) {
        // Anti-cheat detected the buffer overflow attempt
        setCheatDetected(true)
      } else {
        // Show all cards briefly
        setFlipped(Array(16).fill(true))

        // Hide unmatched cards after a moment
        setTimeout(() => {
          const newFlipped = matched.map((m) => m)
          if (firstCard !== null) newFlipped[firstCard] = true
          if (secondCard !== null) newFlipped[secondCard] = true
          setFlipped(newFlipped)
        }, 2000)
      }
    }
  }, [isCheatActive, gameStarted])

  // Get card color based on value
  const getCardColor = (value: number) => {
    const colors = [
      "bg-red-500",
      "bg-blue-500",
      "bg-green-500",
      "bg-yellow-500",
      "bg-purple-500",
      "bg-pink-500",
      "bg-indigo-500",
      "bg-orange-500",
    ]
    return colors[value - 1] || "bg-gray-500"
  }

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <div className="mb-4 flex justify-between w-full max-w-md">
        <div className="text-green-500">Moves: {moves}</div>
        {gameOver && <div className="text-yellow-500">Game Complete!</div>}
      </div>

      {cheatDetected ? (
        <div className="text-center space-y-4">
          <Shield className="h-16 w-16 text-red-500 mx-auto" />
          <h3 className="text-xl font-bold text-red-500">Buffer Overflow Detected!</h3>
          <p className="max-w-md mx-auto text-gray-400">
            The anti-cheat system has detected an attempt to access memory beyond allocated boundaries. This type of
            cheat tries to reveal card positions by reading memory that should be inaccessible.
          </p>
          <Button variant="destructive" onClick={initializeGame}>
            Restart Game
          </Button>
        </div>
      ) : gameStarted ? (
        <div className="grid grid-cols-4 gap-2 bg-gray-800 p-4 rounded-md">
          {cards.map((card, index) => (
            <div
              key={index}
              className={`w-16 h-16 rounded-md cursor-pointer transition-all duration-300 transform ${
                flipped[index] ? "rotate-y-180" : ""
              }`}
              onClick={() => handleCardClick(index)}
            >
              <div className="relative w-full h-full">
                {/* Card back */}
                <div
                  className={`absolute w-full h-full flex items-center justify-center 
                  bg-gray-700 rounded-md ${flipped[index] ? "opacity-0" : "opacity-100"} 
                  transition-opacity duration-300`}
                >
                  <span className="text-white">?</span>
                </div>

                {/* Card front */}
                <div
                  className={`absolute w-full h-full flex items-center justify-center 
                  ${getCardColor(card)} rounded-md ${flipped[index] ? "opacity-100" : "opacity-0"} 
                  transition-opacity duration-300`}
                >
                  <span className="text-white font-bold">{card}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <Button onClick={initializeGame} className="bg-green-600 hover:bg-green-700">
          Start Game
        </Button>
      )}

      {gameOver && !cheatDetected && (
        <div className="mt-4">
          <Button onClick={initializeGame} className="bg-green-600 hover:bg-green-700">
            Play Again
          </Button>
        </div>
      )}

      {isCheatActive && gameStarted && !cheatDetected && (
        <div className="mt-4 text-yellow-500 text-sm">
          Buffer Overflow Cheat Active: Revealing card positions by accessing memory beyond boundaries
        </div>
      )}

      <div className="mt-6 bg-gray-800 p-4 rounded-md max-w-md">
        <h3 className="font-bold text-lg mb-2">How This Cheat Works:</h3>
        <p className="text-sm text-gray-300 mb-3">
          The Buffer Overflow cheat exploits a vulnerability where the game doesn't properly check memory boundaries. By
          reading memory outside the allocated space, the cheat can see card values that should be hidden.
        </p>

        <h3 className="font-bold text-lg mb-2">How Anti-Cheat Blocks It:</h3>
        <p className="text-sm text-gray-300">
          The anti-cheat system validates all memory access attempts. When it detects an attempt to read beyond the
          allowed memory boundaries, it immediately flags the action as cheating and terminates the game session.
        </p>
      </div>
    </div>
  )
}

