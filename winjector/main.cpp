#include "winjector.h"

int main(int argc, char* argv[])
{
	winjector::Winjector Winjector;

	if (argc < 2)
	{
		Winjector.ShowUsage();
		system("pause");
		return 1;
	}

	for (size_t i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-' ||
			argv[i][0] == '/')
		{
			switch (argv[i][1])
			{
				case 'H': case 'h':
				{
					Winjector.ShowUsage();
					system("pause");
					break;
				}

				case 'C': case 'c':
				{
					if (!Winjector.JSONToConfiguration(argv[++i]))
					{
						system("pause");
						return 2;
					}
					break;
				}

				case 'S': case 's':
				{
					if (!Winjector.SaveConfiguration(argv[++i]))
					{
						system("pause");
						return 3;
					}
					break;
				}

				case 'R': case 'r':
				{
					if (!Winjector.ReadConfiguration(argv[i][1]))
					{
						system("pause");
						return 4;
					}
					break;
				}

				case 'B': case 'b':
				{
					if (!Winjector.LoadConfiguration(argv[++i]))
					{
						system("pause");
						return 5;
					}
					break;
				}

				case 'I': case 'i':
				{
					Winjector.SetProcessImagePath(argv[++i]);
					break;
				}

				case 'A': case 'a':
				{
					Winjector.SetProcessCommandLine(argv[++i]);
					break;
				}

				case 'D': case 'd':
				{
					if (!Winjector.LoadDll(argv[++i]))
					{
						system("pause");
						return 6;
					}
					break;
				}

				case 'W':case'w':
				{
					Winjector.SetWaitInjectionFlag(argv[i][1]);
					break;
				}

				case 'E':case'e':
				{
					if (!Winjector.Execute(argv[i][1]))
					{
						system("pause");
						return 7;
					}
					break;
				}

				default: break;
			}
		}
	}

	system("pause");
	return NULL;
}