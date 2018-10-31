package walletseed

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/SHDMT/gravity/infrastructure/crypto/hash"
	"strings"
)

var wordList = strings.Split(alternatingWords, "\n")

var wordIndexes = make(map[string]uint16, len(wordList))

const alternatingWords = `aardvark
adroitness
absurd
adviser
accrue
aftermath
acme
aggregate
adrift
alkali
adult
almighty
afflict
amulet
ahead
amusement
aimless
antenna
Algol
applicant
allow
Apollo
alone
armistice
ammo
article
ancient
asteroid
apple
Atlantic
artist
atmosphere
assume
autopsy
Athens
Babylon
atlas
backwater
Aztec
barbecue
baboon
belowground
backfield
bifocals
backward
bodyguard
banjo
bookseller
beaming
borderline
bedlamp
bottomless
beehive
Bradbury
beeswax
bravado
befriend
Brazilian
Belfast
breakaway
berserk
Burlington
billiard
businessman
bison
butterfat
blackjack
Camelot
blockade
candidate
blowtorch
cannonball
bluebird
Capricorn
bombast
caravan
bookshelf
caretaker
brackish
celebrate
breadline
cellulose
breakup
certify
brickyard
chambermaid
briefcase
Cherokee
Burbank
Chicago
button
clergyman
buzzard
coherence
cement
combustion
chairlift
commando
chatter
company
checkup
component
chisel
concurrent
choking
confidence
chopper
conformist
Christmas
congregate
clamshell
consensus
classic
consulting
classroom
corporate
cleanup
corrosion
clockwork
councilman
cobra
crossover
commence
crucifix
concert
cumbersome
cowbell
customer
crackdown
Dakota
cranky
decadence
crowfoot
December
crucial
decimal
crumpled
designing
crusade
detector
cubic
detergent
dashboard
determine
deadbolt
dictator
deckhand
dinosaur
dogsled
direction
dragnet
disable
drainage
disbelief
dreadful
disruptive
drifter
distortion
dropper
document
drumbeat
embezzle
drunken
enchanting
Dupont
enrollment
dwelling
enterprise
eating
equation
edict
equipment
egghead
escapade
eightball
Eskimo
endorse
everyday
endow
examine
enlist
existence
erase
exodus
escape
fascinate
exceed
filament
eyeglass
finicky
eyetooth
forever
facial
fortitude
fallout
frequency
flagpole
gadgetry
flatfoot
Galveston
flytrap
getaway
fracture
glossary
framework
gossamer
freedom
graduate
frighten
gravity
gazelle
guitarist
Geiger
hamburger
glitter
Hamilton
glucose
handiwork
goggles
hazardous
goldfish
headwaters
gremlin
hemisphere
guidance
hesitate
hamlet
hideaway
highchair
holiness
hockey
hurricane
indoors
hydraulic
indulge
impartial
inverse
impetus
involve
inception
island
indigo
jawbone
inertia
keyboard
infancy
kickoff
inferno
kiwi
informant
klaxon
insincere
locale
insurgent
lockup
integrate
merit
intention
minnow
inventive
miser
Istanbul
Mohawk
Jamaica
mural
Jupiter
music
leprosy
necklace
letterhead
Neptune
liberty
newborn
maritime
nightbird
matchmaker
Oakland
maverick
obtuse
Medusa
offload
megaton
optic
microscope
orca
microwave
payday
midsummer
peachy
millionaire
pheasant
miracle
physique
misnomer
playhouse
molasses
Pluto
molecule
preclude
Montana
prefer
monument
preshrunk
mosquito
printer
narrative
prowler
nebula
pupil
newsletter
puppy
Norwegian
python
October
quadrant
Ohio
quiver
onlooker
quota
opulent
ragtime
Orlando
ratchet
outfielder
rebirth
Pacific
reform
pandemic
regain
Pandora
reindeer
paperweight
rematch
paragon
repay
paragraph
retouch
paramount
revenge
passenger
reward
pedigree
rhythm
Pegasus
ribcage
penetrate
ringbolt
perceptive
robust
performance
rocker
pharmacy
ruffled
phonetic
sailboat
photograph
sawdust
pioneer
scallion
pocketful
scenic
politeness
scorecard
positive
Scotland
potato
seabird
processor
select
provincial
sentence
proximate
shadow
puberty
shamrock
publisher
showgirl
pyramid
skullcap
quantity
skydive
racketeer
slingshot
rebellion
slowdown
recipe
snapline
recover
snapshot
repellent
snowcap
replica
snowslide
reproduce
solo
resistor
southward
responsive
soybean
retraction
spaniel
retrieval
spearhead
retrospect
spellbind
revenue
spheroid
revival
spigot
revolver
spindle
sandalwood
spyglass
sardonic
stagehand
Saturday
stagnate
savagery
stairway
scavenger
standard
sensation
stapler
sociable
steamship
souvenir
sterling
specialist
stockman
speculate
stopwatch
stethoscope
stormy
stupendous
sugar
supportive
surmount
surrender
suspense
suspicious
sweatband
sympathy
swelter
tambourine
tactics
telephone
talon
therapist
tapeworm
tobacco
tempest
tolerance
tiger
tomorrow
tissue
torpedo
tonic
tradition
topmost
travesty
tracker
trombonist
transit
truncated
trauma
typewriter
treadmill
ultimate
Trojan
undaunted
trouble
underfoot
tumor
unicorn
tunnel
unify
tycoon
universe
uncut
unravel
unearth
upcoming
unwind
vacancy
uproot
vagabond
upset
vertigo
upshot
Virginia
vapor
visitor
village
vocalist
virus
voyager
Vulcan
warranty
waffle
Waterloo
wallet
whimsical
watchword
Wichita
wayside
Wilmington
willow
Wyoming
woodlark
yesteryear
Zulu
Yucatan`

const (
	// MinSeedBytes the minimum seed length that the wallet supports
	MinSeedBytes         = 16
	// MaxSeedBytes the maximum seed length that the wallet supports
	MaxSeedBytes         = 64
	// RecommendedSeedBytes the recommended seed length that the wallet supports
	RecommendedSeedBytes = 32
)

// const ChainMaster string
const (
	ChainMaster = "Gravity seed"
)

func init() {
	for i, word := range wordList {
		wordIndexes[strings.ToLower(word)] = uint16(i)
	}
}

// GenerateSeed generate a seed with specified length
func GenerateSeed(length uint8) ([]byte, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if length < MinSeedBytes || length > MaxSeedBytes {
		return nil, errors.New("error seed length ")
	}

	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// EncodeMnemonicSlice Convert seed in []byte format to seed in word list format
func EncodeMnemonicSlice(seed []byte) []string {
	words := make([]string, len(seed)+1) // Extra word for checksumByte
	for i, b := range seed {
		words[i] = byteToMnemonic(b, i)
	}
	checksum := checksumByte(seed)
	words[len(words)-1] = byteToMnemonic(checksum, len(seed))
	return words
}

func checksumByte(data []byte) byte {
	intermediateHash := hash.Sum256(data)
	return hash.Sum256(intermediateHash[:])[0]
}

func byteToMnemonic(b byte, index int) string {
	bb := uint16(b) * 2
	if index%2 != 0 {
		bb++
	}
	return wordList[bb]
}

// DecodeMnemonics returns the decoded value that is encoded by words.  Any
// words that are whitespace are empty are skipped.
func decodeMnemonics(words []string) ([]byte, error) {
	decoded := make([]byte, len(words))
	idx := 0
	for _, w := range words {
		w = strings.TrimSpace(w)
		if w == "" {
			continue
		}
		b, ok := wordIndexes[strings.ToLower(w)]
		if !ok {
			return nil, fmt.Errorf("word %v is not in the PGP word list", w)
		}
		if int(b%2) != idx%2 {
			return nil, fmt.Errorf("word %v is not valid at position %v, "+
				"check for missing words", w, idx)
		}
		decoded[idx] = byte(b / 2)
		idx++
	}
	return decoded[:idx], nil
}

// DecodeUserInput Convert the seed of the word list format entered by the user to []byte format
func DecodeUserInput(input string) ([]byte, error) {
	words := strings.Split(strings.TrimSpace(input), " ")
	var seed []byte
	switch {
	case len(words) == 1:
		// Assume hex
		var err error
		seed, err = hex.DecodeString(words[0])
		if err != nil {
			return nil, err
		}
	case len(words) > 1:
		// Assume mnemonic with encoded checksum byte
		decoded, err := decodeMnemonics(words)
		if err != nil {
			return nil, err
		}
		if len(decoded) < 2 { // need data (0) and checksum (1) to check checksum
			break
		}
		if checksumByte(decoded[:len(decoded)-1]) != decoded[len(decoded)-1] {
			return nil, errors.New("checksum mismatch")
		}
		seed = decoded[:len(decoded)-1]
	}

	if len(seed) < MinSeedBytes || len(seed) > MaxSeedBytes {
		return nil, errors.New(" seed length error. ")
	}
	return seed, nil
}
