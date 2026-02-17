"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { useAuth } from "@/hooks/use-auth"
import { GraduationCap, Loader2 } from "lucide-react"
import { TotpSetup } from "./totp-setup"

export function SignUpForm() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")
  const [showTotpSetup, setShowTotpSetup] = useState(false)
  const { signUp, refreshUser } = useAuth()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError("")

    try {
      await signUp(email, password)
    } catch (error: any) {
      // Проверяем, требуется ли настройка TOTP
      const errorMessage = error?.message || error?.toString() || ""
      if (errorMessage.includes("totp_secret_required") || errorMessage.includes("Требуется двухфакторная авторизация")) {
        setShowTotpSetup(true)
      } else {
        setError("Ошибка регистрации. Проверьте данные и попробуйте снова.")
      }
    } finally {
      setIsLoading(false)
    }
  }

  const handleTotpComplete = async () => {
    await refreshUser()
    setShowTotpSetup(false)
  }

  if (showTotpSetup) {
    return <TotpSetup onComplete={handleTotpComplete} onBack={() => setShowTotpSetup(false)} />
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <Card className="w-full max-w-md mx-auto">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <GraduationCap className="h-12 w-12 text-primary" />
          </div>
          <CardTitle className="text-2xl">Добро пожаловать</CardTitle>
          <CardDescription>Войдите в систему с помощью учетных данных МИРЭА</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email">Email МИРЭА</Label>
              <Input
                id="email"
                type="email"
                placeholder="kupitman.i.n@edu.mirea.ru"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={isLoading}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Пароль</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={isLoading}
              />
            </div>
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Войти
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
