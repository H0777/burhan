import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { OidcCallbackHandler } from './LoginScreen.jsx'

// OidcCallbackHandler consumes useAuth from AuthProvider only for completeLogin;
// mock the module so the handler is exercised in isolation.
const completeLoginMock = vi.fn()
vi.mock('./AuthProvider.jsx', () => ({
  useAuth: () => ({ completeLogin: completeLoginMock }),
}))

/**
 * H05 regression: the callback URL carries a SINGLE-USE authorization code, so
 * OidcCallbackHandler must call completeLogin exactly ONCE even when App
 * re-renders mid-flight (the inline onDone prop changes identity on every
 * render, which re-triggers the effect through its dependency list). The
 * pre-fix behavior raced the code exchange against itself — the provider saw
 * two token POSTs for one login (200 then 400 "code already used") and the UI
 * landed on the error screen despite a successful session.
 */
describe('OidcCallbackHandler — single-use callback code', () => {
  beforeEach(() => {
    completeLoginMock.mockReset()
    window.history.replaceState({}, '', '/auth/callback')
  })

  it('calls completeLogin exactly once across re-renders and surfaces done + onDone', async () => {
    completeLoginMock.mockResolvedValue(undefined)

    const onDone = vi.fn()
    const { rerender } = render(<OidcCallbackHandler onDone={onDone} />)
    // App re-renders while the exchange is in flight (isLoading flip) — each
    // render re-creates the inline onDone arrow and would re-run the effect
    // through its dependency list.
    rerender(<OidcCallbackHandler onDone={() => {}} />)
    rerender(<OidcCallbackHandler onDone={() => {}} />)

    expect(completeLoginMock).toHaveBeenCalledTimes(1)
    expect(completeLoginMock).toHaveBeenCalledWith(window.location.href)

    await waitFor(() => expect(screen.getByTestId('callback-done')).toBeTruthy())
    expect(onDone).toHaveBeenCalledTimes(1)
  })

  it('renders the error state exactly once when the callback is rejected', async () => {
    completeLoginMock.mockRejectedValue(new Error('callback state was already consumed'))

    const { rerender } = render(<OidcCallbackHandler onDone={() => {}} />)
    rerender(<OidcCallbackHandler onDone={() => {}} />)

    await waitFor(() => expect(screen.getByTestId('callback-error')).toBeTruthy())
    expect(completeLoginMock).toHaveBeenCalledTimes(1)
  })
})
