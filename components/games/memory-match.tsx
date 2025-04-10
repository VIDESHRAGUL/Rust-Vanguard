"use client"

import { useEffect, useState, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Shield } from "lucide-react"

interface MemoryMatchGameProps {
  isCheatActive: boolean
}

export default function MemoryMatchGame({ isCheatActive }: MemoryMatchGameProps) {
  const [cards, setCards] = useState<number[]>([])
  const [flipped, setFlipped] = useState<boolean[]>([])
  const [matched, setMatched] = useState<boolean[]>([])
  const [moves, setMoves] = useState(0)
  const [gameStarted, setGameStarted] = useState(false)
  const [gameOver, setGameOver] = useState(false)
  const [firstSelection, setFirstSelection] = useState<number | null>(null)
  const [secondSelection, setSecondSelection] = useState<number | null>(null)
  const [isChecking, setIsChecking] = useState(false)
  const [cheatDetected, setCheatDetected] = useState(false)

  // Anti-cheat reference
  const memoryBufferRef = useRef<number[]>([])

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
    setGameStarted(true)
    setGameOver(false)
    setFirstSelection(null)
    setSecondSelection(null)
    setCheatDetected(false)

    // Initialize anti-cheat memory buffer
    memoryBufferRef.current = Array(16).fill(0)
  }

  // Handle card click
  const handleCardClick = (index: number) => {
    // Don't allow flipping if already checking a pair or card is already flipped/matched
    if (isChecking || flipped[index] || matched[index] || cheatDetected) return

    // Create new flipped state
    const newFlipped = [...flipped]
    newFlipped[index] = true

    // Update selections
    if (firstSelection === null) {
      setFirstSelection(index)
    } else if (secondSelection === null) {
      setSecondSelection(index)
      setIsChecking(true)
      setMoves(moves + 1)
    }

    setFlipped(newFlipped)
  }

  // Check for matches
  useEffect(() => {
    if (firstSelection !== null && secondSelection !== null) {
      // Check if the cards match
      if (cards[firstSelection] === cards[secondSelection]) {
        // Cards match
        const newMatched = [...matched]
        newMatched[firstSelection] = true
        newMatched[secondSelection] = true
        setMatched(newMatched)

        // Reset selections
        setFirstSelection(null)
        setSecondSelection(null)
        setIsChecking(false)

        // Check if game is over
        if (newMatched.every((m) => m)) {
          setGameOver(true)
        }
      } else {
        // Cards don't match, flip them back after a delay
        setTimeout(() => {
          const newFlipped = [...flipped]
          newFlipped[firstSelection] = false
          newFlipped[secondSelection] = false
          setFlipped(newFlipped)

          // Reset selections
          setFirstSelection(null)
          setSecondSelection(null)
          setIsChecking(false)
        }, 1000)
      }
    }
  }, [firstSelection, secondSelection, cards, flipped, matched])

  // Apply cheat if active
  useEffect(() => {
    if (isCheatActive && gameStarted && !gameOver) {
      // Buffer Overflow Cheat: Reveal all cards by overflowing the memory buffer
      try {
        // Simulate buffer overflow by writing beyond the allocated memory
        const overflowBuffer = [...memoryBufferRef.current]

        // In a real buffer overflow, we'd write beyond the allocated memory
        // Here we're simulating it by writing to all positions
        for (let i = 0; i < cards.length; i++) {
          overflowBuffer[i] = cards[i]
        }

        // Anti-cheat detection
        if (isAntiCheatActive) {
          // Check if buffer has been overflowed (in a real system, this would be more sophisticated)
          if (overflowBuffer.some((val, idx) => val !== memoryBufferRef.current[idx])) {
            console.log("Anti-cheat: Buffer overflow detected!")
            setCheatDetected(true)
            return
          }
        }

        // If anti-cheat is not active or didn't detect the cheat, reveal all cards
        if (!isAntiCheatActive) {
          setFlipped(Array(16).fill(true))
        }
      } catch (error) {
        console.error("Cheat error:", error)
      }
    }
  }, [isCheatActive, gameStarted, gameOver, cards])

  // Anti-cheat active state
  const isAntiCheatActive = gameStarted && !gameOver && window.isAntiCheatActive

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
          <h3 className="text-xl font-bold text-red-500">Buffer Overflow Detected!</h3>
          <p className="text-gray-300">
            The anti-cheat system has detected an attempt to access memory outside the allocated buffer.
          </p>
          <Button onClick={initializeGame} className="bg-green-600 hover:bg-green-700">
            Restart Game
          </Button>
        </div>
      ) : gameStarted ? (
        <div className="grid grid-cols-4 gap-2">
          {cards.map((card, index) => (
            <div
              key={index}
              className={`w-16 h-16 flex items-center justify-center rounded-md cursor-pointer transition-all duration-300 transform
                ${
                  flipped[index] || (isCheatActive && !isAntiCheatActive)
                    ? "bg-blue-600 rotate-y-0"
                    : "bg-gray-700 rotate-y-180"
                }
                ${matched[index] ? "bg-green-600" : ""}
                hover:bg-opacity-90`}
              onClick={() => handleCardClick(index)}
            >
              {(flipped[index] || matched[index] || (isCheatActive && !isAntiCheatActive)) && (
                <span className="text-white text-xl font-bold">{card}</span>
              )}
            </div>
          ))}
        </div>
      ) : (
        <Button onClick={initializeGame} className="bg-green-600 hover:bg-green-700">
          Start Game
        </Button>
      )}

      {gameOver && (
        <div className="mt-4 text-center">
          <p className="text-green-500 mb-2">Congratulations! You completed the game in {moves} moves.</p>
          <Button onClick={initializeGame} className="bg-green-600 hover:bg-green-700">
            Play Again
          </Button>
        </div>
      )}

      {isCheatActive && gameStarted && !gameOver && !cheatDetected && (
        <div className="mt-4 text-yellow-500 text-sm">
          Buffer Overflow Cheat Active: Attempting to reveal all cards by accessing memory outside the allocated buffer
        </div>
      )}

      <div className="mt-6 p-4 bg-gray-800/50 rounded-lg max-w-md">
        <h3 className="text-lg font-semibold mb-2">How the Cheat Works:</h3>
        <p className="text-sm text-gray-300 mb-3">
          The Buffer Overflow cheat attempts to access memory beyond what's allocated for the game state. By writing
          beyond the memory boundaries, it can reveal the positions of all cards.
        </p>

        <h3 className="text-lg font-semibold mb-2">How Anti-Cheat Blocks It:</h3>
        <p className="text-sm text-gray-300">
          The Memory Integrity Verification anti-cheat system monitors the memory boundaries and detects when a program
          tries to access or modify memory outside its allocated space. When detected, it immediately terminates the
          cheat attempt and protects the game state.
        </p>
      </div>
    </div>
  )
}

