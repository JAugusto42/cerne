from cerne.app import CerneApp

def main():
    """ Entrypoint when is installed via pip """
    app = CerneApp()
    app.run()

# Development mode
if __name__ == "__main__":
    main()