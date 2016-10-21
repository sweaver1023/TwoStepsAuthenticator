using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TwoStepsAuthenticator
{

    /// <summary>
    /// Implementation of RFC 4226 Counter-Based One-Time Password Algorithm
    /// </summary>
    public class CounterAuthenticator : Authenticator
    {
        private readonly int WindowSize;
        private readonly int CodeLength;

        public CounterAuthenticator(int windowSize = 10, int codeLength = 8) {
            if (windowSize <= 0) {
                throw new ArgumentException("look-ahead window size must be positive");
            }

            this.WindowSize = windowSize;
            this.CodeLength = codeLength;
        }

        /// <summary>
        /// Generates One-Time-Password.
        /// </summary>
        /// <param name="secret">Shared Secret</param>
        /// <param name="counter">Current Counter</param>
        /// <returns>OTP</returns>
        public string GetCode(string secret, ulong counter)
        {
            return GetCodeInternal(secret, counter, CodeLength);
        }

        /// <summary>
        /// Checks if the passed code is valid.
        /// </summary>
        /// <param name="secret">Shared Secret</param>
        /// <param name="code">OTP</param>
        /// <param name="counter">Current Counter Position</param>
        /// <returns>true if any code from counter to counter + WindowSize matches</returns>
        public bool CheckCode(string secret, string code, ulong counter)
        {
            ulong successfulSequenceNumber = 0uL;

            return CheckCode(secret, code, counter, out successfulSequenceNumber);
        }

        /// <summary>
        /// Checks if the passed code is valid.
        /// </summary>
        /// <param name="secret">Shared Secret</param>
        /// <param name="code">OTP</param>
        /// <param name="counter">Current Counter Position</param>
        /// <param name="usedCounter">Matching counter value if successful</param>
        /// <returns>true if any code from counter to counter + WindowSize matches</returns>
        public bool CheckCode(string secret, string code, ulong counter, out ulong usedCounter)
        {
            var codeMatch = false;
            ulong successfulSequenceNumber = 0uL;

            for (uint i = 0; i <= WindowSize; i++)
            {
                ulong checkCounter = counter + i;
                if (ConstantTimeEquals(GetCode(secret, checkCounter), code)) {
                    codeMatch = true;
                    successfulSequenceNumber = checkCounter;
                }
            }

            usedCounter = successfulSequenceNumber;
            return codeMatch;
        }
    }
}
