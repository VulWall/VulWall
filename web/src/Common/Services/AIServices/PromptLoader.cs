using Microsoft.Extensions.Caching.Memory;

namespace VulWall.Dashboard.Common.Services.AIServices;

public class PromptLoader(IMemoryCache cache)
{
    private static readonly string PromptsDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Prompts");

    public async Task<string> LoadPromptFromFileAsync(string promptName)
    {
        var cacheKey = $"prompt_{promptName}";
        
        // Check cache first
        if (cache.TryGetValue(cacheKey, out string? cachedPrompt))
        {
            return cachedPrompt!;
        }

        // Try exact match first
        var promptFilePath = Path.Combine(PromptsDirectory, $"{promptName}.txt");
        
        if (!File.Exists(promptFilePath))
        {
            // Try case-insensitive search
            var files = Directory.GetFiles(PromptsDirectory, "*.txt");
            var matchingFile = files.FirstOrDefault(f => 
                Path.GetFileNameWithoutExtension(f).Equals(promptName, StringComparison.OrdinalIgnoreCase));
            
            if (matchingFile != null)
            {
                promptFilePath = matchingFile;
            }
            else
            {
                throw new FileNotFoundException($"Prompt file not found: {promptFilePath}");
            }
        }

        var prompt = await File.ReadAllTextAsync(promptFilePath);
        
        // Cache the prompt with expiration (1 hour)
        var cacheOptions = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1),
            SlidingExpiration = TimeSpan.FromMinutes(30)
        };
        
        cache.Set(cacheKey, prompt, cacheOptions);

        return prompt;
    }
} 