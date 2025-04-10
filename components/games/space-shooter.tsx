"use client"

import { useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Shield } from "lucide-react"

interface SpaceShooterGameProps {
  isCheatActive: boolean
}

export default function SpaceShooterGame({ isCheatActive }: SpaceShooterGameProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [gameStarted, setGameStarted] = useState(false)
  const [score, setScore] = useState(0)
  const [gameOver, setGameOver] = useState(false)
  const [cheatDetected, setCheatDetected] = useState(false)

  useEffect(() => {
    if (!gameStarted || !canvasRef.current) return

    const canvas = canvasRef.current
    const ctx = canvas.getContext("2d")
    if (!ctx) return

    // Game variables
    let playerX = canvas.width / 2
    const playerY = canvas.height - 30
    const playerWidth = 30
    const playerHeight = 15
    let rightPressed = false
    let leftPressed = false
    let spacePressed = false
    let lastShotTime = 0
    const shotCooldown = 500 // ms
    let currentScore = 0
    let enemies: { x: number; y: number; width: number; height: number; speed: number }[] = []
    let bullets: { x: number; y: number; width: number; height: number; speed: number }[] = []
    let lastFrameTime = Date.now()
    let gameSpeed = 1
    let timeManipulationDetected = false

    // Create enemies
    const createEnemies = () => {
      enemies = []
      for (let i = 0; i < 10; i++) {
        enemies.push({
          x: Math.random() * (canvas.width - 20),
          y: Math.random() * 150 + 10,
          width: 20,
          height: 20,
          speed: 1 + Math.random(),
        })
      }
    }

    // Event listeners
    const keyDownHandler = (e: KeyboardEvent) => {
      if (e.key === "Right" || e.key === "ArrowRight") {
        rightPressed = true
      } else if (e.key === "Left" || e.key === "ArrowLeft") {
        leftPressed = true
      } else if (e.key === " ") {
        spacePressed = true
      }
    }

    const keyUpHandler = (e: KeyboardEvent) => {
      if (e.key === "Right" || e.key === "ArrowRight") {
        rightPressed = false
      } else if (e.key === "Left" || e.key === "ArrowLeft") {
        leftPressed = false
      } else if (e.key === " ") {
        spacePressed = false
      }
    }

    document.addEventListener("keydown", keyDownHandler)
    document.addEventListener("keyup", keyUpHandler)

    // Shoot function
    const shoot = () => {
      const now = Date.now()
      if (now - lastShotTime > shotCooldown) {
        bullets.push({
          x: playerX + playerWidth / 2 - 2,
          y: playerY,
          width: 4,
          height: 10,
          speed: 5,
        })
        lastShotTime = now
      }
    }

    // Check collision
    const checkCollision = (
      rect1: { x: number; y: number; width: number; height: number },
      rect2: { x: number; y: number; width: number; height: number },
    ) => {
      return (
        rect1.x < rect2.x + rect2.width &&
        rect1.x + rect1.width > rect2.x &&
        rect1.y < rect2.y + rect2.height &&
        rect1.y + rect1.height > rect2.y
      )
    }

    // Draw player
    const drawPlayer = () => {
      ctx.fillStyle = "#0095DD"
      ctx.beginPath()
      ctx.moveTo(playerX, playerY)
      ctx.lineTo(playerX + playerWidth, playerY)
      ctx.lineTo(playerX + playerWidth / 2, playerY - playerHeight)
      ctx.fill()
    }

    // Draw enemies
    const drawEnemies = () => {
      enemies.forEach((enemy) => {
        ctx.fillStyle = "#DD0000"
        ctx.fillRect(enemy.x, enemy.y, enemy.width, enemy.height)
      })
    }

    // Draw bullets
    const drawBullets = () => {
      bullets.forEach((bullet) => {
        ctx.fillStyle = "#FFFFFF"
        ctx.fillRect(bullet.x, bullet.y, bullet.width, bullet.height)
      })
    }

    // Draw score
    const drawScore = () => {
      ctx.font = "16px Arial"
      ctx.fillStyle = "#FFFFFF"
      ctx.fillText(`Score: ${currentScore}`, 8, 20)
    }

    // Main game loop
    const draw = () => {
      // Calculate delta time for time-based movement
      const currentTime = Date.now()
      let deltaTime = (currentTime - lastFrameTime) / 16.67 // Normalize to ~60fps

      // Apply time manipulation cheat if active
      if (isCheatActive && !isAntiCheatActive) {
        gameSpeed = 0.3 // Slow down the game significantly
        deltaTime *= gameSpeed
      } else {
        gameSpeed = 1
      }

      // Anti-cheat: Detect time manipulation
      if (isAntiCheatActive && isCheatActive) {
        // In a real anti-cheat, this would be more sophisticated
        // Here we're just checking if the game speed has been modified
        if (gameSpeed !== 1) {
          timeManipulationDetected = true
          setCheatDetected(true)
          setGameStarted(false)
          return
        }
      }

      lastFrameTime = currentTime

      // Clear canvas
      ctx.clearRect(0, 0, canvas.width, canvas.height)

      // Draw game elements
      drawPlayer()
      drawEnemies()
      drawBullets()
      drawScore()

      // Move player
      if (rightPressed && playerX < canvas.width - playerWidth) {
        playerX += 5 * deltaTime
      } else if (leftPressed && playerX > 0) {
        playerX -= 5 * deltaTime
      }

      // Shoot if space is pressed
      if (spacePressed) {
        shoot()
      }

      // Move bullets
      bullets = bullets.filter((bullet) => {
        bullet.y -= bullet.speed * deltaTime
        return bullet.y > 0
      })

      // Move enemies
      enemies.forEach((enemy) => {
        enemy.y += enemy.speed * deltaTime

        // Check if enemy reached bottom
        if (enemy.y > canvas.height) {
          enemy.y = 0
          enemy.x = Math.random() * (canvas.width - enemy.width)
        }

        // Check collision with player
        if (
          checkCollision({ x: playerX, y: playerY - playerHeight, width: playerWidth, height: playerHeight }, enemy)
        ) {
          setGameOver(true)
          setGameStarted(false)
          return
        }
      })

      // Check bullet-enemy collisions
      bullets = bullets.filter((bullet) => {
        let bulletHit = false

        enemies = enemies.filter((enemy) => {
          if (checkCollision(bullet, enemy) && !bulletHit) {
            bulletHit = true
            currentScore++
            setScore(currentScore)

            // Respawn enemy at top
            enemy.y = 0
            enemy.x = Math.random() * (canvas.width - enemy.width)
            return true
          }
          return true
        })

        return !bulletHit
      })

      if (gameStarted && !gameOver && !timeManipulationDetected) {
        requestAnimationFrame(draw)
      }
    }

    // Start the game
    createEnemies()
    lastFrameTime = Date.now()
    draw()

    return () => {
      document.removeEventListener("keydown", keyDownHandler)
      document.removeEventListener("keyup", keyUpHandler)
    }
  }, [gameStarted, isCheatActive])

  const startGame = () => {
    setGameStarted(true)
    setGameOver(false)
    setScore(0)
    setCheatDetected(false)
  }

  // Anti-cheat active state
  const isAntiCheatActive = gameStarted && !gameOver && window.isAntiCheatActive

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <div className="mb-4 flex justify-between w-full max-w-md">
        <div className="text-blue-500">Score: {score}</div>
        {isAntiCheatActive && (
          <div className="flex items-center text-green-500">
            <Shield className="h-4 w-4 mr-1" />
            Anti-Cheat Active
          </div>
        )}
      </div>

      {cheatDetected ? (
        <div className="text-center space-y-4 p-6 bg-red-900/20 rounded-lg">
          <h3 className="text-xl font-bold text-red-500">Time Manipulation Detected!</h3>
          <p className="text-gray-300">
            The anti-cheat system has detected an attempt to manipulate the game's timing.
          </p>
          <Button onClick={startGame} className="bg-green-600 hover:bg-green-700">
            Restart Game
          </Button>
        </div>
      ) : (
        <>
          <canvas ref={canvasRef} width={480} height={320} className="bg-gray-900 border border-gray-700 rounded-md" />

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
        </>
      )}

      {isCheatActive && gameStarted && !gameOver && !cheatDetected && (
        <div className="mt-4 text-yellow-500 text-sm">
          Time Manipulation Cheat Active: Slowing down game time for player advantage
        </div>
      )}

      <div className="mt-6 p-4 bg-gray-800/50 rounded-lg max-w-md">
        <h3 className="text-lg font-semibold mb-2">How the Cheat Works:</h3>
        <p className="text-sm text-gray-300 mb-3">
          The Time Manipulation cheat works by artificially slowing down the game's clock. This gives the player more
          time to react to enemies and makes the game much easier. It's like playing in slow motion while still having
          normal reaction time.
        </p>

        <h3 className="text-lg font-semibold mb-2">How Anti-Cheat Blocks It:</h3>
        <p className="text-sm text-gray-300">
          The Server-side Verification anti-cheat system monitors the timing between game events and actions. It
          compares the client's reported time with the server's time to detect inconsistencies. When it detects that the
          game is running slower than it should, it identifies this as cheating and terminates the game session.
        </p>
      </div>

      <div className="mt-4 text-sm text-gray-400">Use ← → arrow keys to move and SPACE to shoot</div>
    </div>
  )
}

