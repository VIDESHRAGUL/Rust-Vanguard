"use client"

import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"

interface SnakeGameProps {
  isCheatActive: boolean
}

export default function SnakeGame({ isCheatActive }: SnakeGameProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [gameStarted, setGameStarted] = useState(false)
  const [score, setScore] = useState(0)
  const [gameOver, setGameOver] = useState(false)

  useEffect(() => {
    if (!gameStarted || !canvasRef.current) return

    const canvas = canvasRef.current
    const ctx = canvas.getContext("2d")
    if (!ctx) return

    // Game variables
    const gridSize = 20
    const tileCount = canvas.width / gridSize
    const snake = [{ x: 10, y: 10 }]
    let food = { x: 5, y: 5 }
    let velocityX = 0
    let velocityY = 0
    let currentScore = 0
    let gameSpeed = 7
    let lastRenderTime = 0

    // Generate random food position
    function placeFood() {
      food = {
        x: Math.floor(Math.random() * tileCount),
        y: Math.floor(Math.random() * tileCount),
      }

      // Make sure food doesn't spawn on snake
      for (let i = 0; i < snake.length; i++) {
        if (snake[i].x === food.x && snake[i].y === food.y) {
          placeFood()
          break
        }
      }
    }

    // Event listeners
    const keyDownHandler = (e: KeyboardEvent) => {
      // Prevent reversing direction
      if (e.key === "ArrowUp" && velocityY !== 1) {
        velocityX = 0
        velocityY = -1
      } else if (e.key === "ArrowDown" && velocityY !== -1) {
        velocityX = 0
        velocityY = 1
      } else if (e.key === "ArrowLeft" && velocityX !== 1) {
        velocityX = -1
        velocityY = 0
      } else if (e.key === "ArrowRight" && velocityX !== -1) {
        velocityX = 1
        velocityY = 0
      }
    }

    document.addEventListener("keydown", keyDownHandler)

    // Game loop
    function gameLoop(currentTime: number) {
      if (!gameStarted) return

      window.requestAnimationFrame(gameLoop)

      // Control game speed
      const secondsSinceLastRender = (currentTime - lastRenderTime) / 1000
      if (secondsSinceLastRender < 1 / gameSpeed) return
      lastRenderTime = currentTime

      // Clear canvas
      ctx.fillStyle = "#1f2937"
      ctx.fillRect(0, 0, canvas.width, canvas.height)

      // Apply cheat if active
      if (isCheatActive) {
        // Code injection cheat: Show path to food
        ctx.strokeStyle = "rgba(255, 255, 0, 0.3)"
        ctx.lineWidth = 5
        ctx.beginPath()
        ctx.moveTo(snake[0].x * gridSize + gridSize / 2, snake[0].y * gridSize + gridSize / 2)
        ctx.lineTo(food.x * gridSize + gridSize / 2, food.y * gridSize + gridSize / 2)
        ctx.stroke()
      }

      // Move snake
      const head = { x: snake[0].x + velocityX, y: snake[0].y + velocityY }

      // Check for wall collision
      if (head.x < 0 || head.x >= tileCount || head.y < 0 || head.y >= tileCount) {
        endGame()
        return
      }

      // Check for self collision
      for (let i = 0; i < snake.length; i++) {
        if (head.x === snake[i].x && head.y === snake[i].y) {
          endGame()
          return
        }
      }

      // Add new head
      snake.unshift(head)

      // Check for food collision
      if (head.x === food.x && head.y === food.y) {
        currentScore++
        setScore(currentScore)
        placeFood()
        // Increase speed slightly
        gameSpeed += 0.2
      } else {
        // Remove tail if no food eaten
        snake.pop()
      }

      // Draw food
      ctx.fillStyle = "#ef4444"
      ctx.fillRect(food.x * gridSize, food.y * gridSize, gridSize, gridSize)

      // Draw snake
      ctx.fillStyle = "#10b981"
      for (let i = 0; i < snake.length; i++) {
        ctx.fillRect(snake[i].x * gridSize, snake[i].y * gridSize, gridSize, gridSize)

        // Draw eyes on head
        if (i === 0) {
          ctx.fillStyle = "#ffffff"
          // Left eye
          ctx.fillRect(
            snake[i].x * gridSize + gridSize / 4,
            snake[i].y * gridSize + gridSize / 4,
            gridSize / 6,
            gridSize / 6,
          )
          // Right eye
          ctx.fillRect(
            snake[i].x * gridSize + (gridSize * 3) / 4 - gridSize / 6,
            snake[i].y * gridSize + gridSize / 4,
            gridSize / 6,
            gridSize / 6,
          )
          ctx.fillStyle = "#10b981"
        }
      }
    }

    function endGame() {
      setGameOver(true)
      setGameStarted(false)
    }

    // Start game
    placeFood()
    window.requestAnimationFrame(gameLoop)

    return () => {
      document.removeEventListener("keydown", keyDownHandler)
    }
  }, [gameStarted, isCheatActive])

  const startGame = () => {
    setGameStarted(true)
    setGameOver(false)
    setScore(0)
  }

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <div className="mb-4 flex justify-between w-full max-w-md">
        <div className="text-green-500">Score: {score}</div>
      </div>

      <canvas ref={canvasRef} width={400} height={400} className="bg-gray-800 border border-gray-700 rounded-md" />

      {!gameStarted && (
        <div className="mt-4">
          <Button onClick={startGame} className="bg-green-600 hover:bg-green-700">
            {gameOver ? "Play Again" : "Start Game"}
          </Button>
          {gameOver && (
            <div className="mt-2 text-center">
              <p className="text-red-500">Game Over! Final score: {score}</p>
            </div>
          )}
        </div>
      )}

      {isCheatActive && gameStarted && (
        <div className="mt-4 text-yellow-500 text-sm">Code Injection Cheat Active: Path to food revealed</div>
      )}

      <div className="mt-4 text-sm text-gray-400">Use arrow keys to control the snake</div>
    </div>
  )
}

