/**
 * Typed errors for @browsercore/testing.
 */

/** Base class for every testing error. */
export class TestingError extends Error {
    public readonly kind = "TestingError" as const;
    public override readonly cause: Error | undefined;

    constructor(message: string, options?: { cause?: Error }) {
        super(message, options);
        this.name = new.target.name;
        this.cause = options?.cause;
    }
}

/** Actual bytes diverged from a golden capture. */
export class GoldenMismatchError extends Error {
    public readonly kind = "GoldenMismatchError" as const;
    public readonly captureId: string;
    public readonly divergenceByteIndex: number;
    public override readonly cause: Error | undefined;

    constructor(
        captureId: string,
        divergenceByteIndex: number,
        options?: { cause?: Error },
    ) {
        super(
            `Golden capture ${captureId} diverges at byte ${divergenceByteIndex}`,
            options,
        );
        this.name = "GoldenMismatchError";
        this.captureId = captureId;
        this.divergenceByteIndex = divergenceByteIndex;
        this.cause = options?.cause;
    }
}
