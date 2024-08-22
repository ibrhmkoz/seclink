import asyncio


async def retry_with_exponential_backoff(callback, max_tries=5, base_wait_time=1):
    for attempt in range(max_tries):
        try:
            return await callback()
        except TimeoutError:
            if attempt == max_tries - 1:
                raise
            wait_time = base_wait_time * (2 ** attempt)
            print(f"Attempt {attempt + 1} failed. Waiting {wait_time} seconds before retrying...")
            await asyncio.sleep(wait_time)
