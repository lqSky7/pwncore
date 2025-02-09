import logging
from datetime import date

from fastapi import APIRouter, Request, Response, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.status import HTTP_401_UNAUTHORIZED
from passlib.hash import bcrypt
from tortoise.transactions import atomic, in_transaction

import pwncore.containerASD as containerASD
from pwncore.config import config
from pwncore.models import (
    Hint,
    PreEventProblem,
    PreEventSolvedProblem,
    Problem,
    Team,
    User,
)
from pwncore.models.ctf import SolvedProblem
from pwncore.models.pre_event import PreEventUser

metadata = {
    "name": "admin",
    "description": "Admin routes (currently only running when development on)",
}

# TODO: Make this protected
router = APIRouter(prefix="/admin", tags=["admin"])
security = HTTPBasic()

if config.development:
    logging.basicConfig(level=logging.INFO)

NAMES = [
    "Mimas",
    "Enceladus",
    "Tethys",
    "Dione",
    "Rhea",
    "Titan",
    "Hyperion",
    "Iapetus",
    "Phoebe",
    "Janus",
    "Epimetheus",
    "Pan",
]


async def _del_cont(id: str):
    container = await containerASD.docker_client.containers.get(id)
    await container.kill()
    await container.delete()


def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = config.admin_username
    correct_password = config.admin_password
    
    if credentials.username != correct_username or credentials.password != correct_password:
        return False
    return True

@atomic()
@router.get("/union")
async def calculate_team_coins(
    credentials: HTTPBasicCredentials = Depends(security)
):
    if not verify_admin(credentials):
        return Response(status_code=HTTP_401_UNAUTHORIZED)
    
    async with in_transaction():
        logging.info("Calculating team points form pre-event CTFs:")
        team_ids = await Team.filter().values_list("id", flat=True)
        results = []
        for team_id in team_ids:
            member_tags = await User.filter(team_id=team_id).values_list(
                "tag", flat=True
            )

            if not member_tags:
                return {"status": "error", "message": "No team members found"}

            problems_solved = set(
                await PreEventSolvedProblem.filter(user_id__in=member_tags).values_list(
                    "problem_id", flat=True
                )
            )

            team = await Team.get(id=team_id)
            for ctf_id in problems_solved:
                team.coins += (await PreEventProblem.get(id=ctf_id)).points
            logging.info(f"{team.id}) {team.name}: {team.coins}")
            await team.save()
            results.append({"team_id": team.id, "name": team.name, "coins": team.coins})
        
        return {"status": "success", "message": "Team coins calculated successfully", "results": results}

@router.get("/create")
async def init_db(
    credentials: HTTPBasicCredentials = Depends(security)
):
    if not verify_admin(credentials):
        return Response(status_code=HTTP_401_UNAUTHORIZED)
    
    try:
        await Problem.create(
            name="Invisible-Incursion",
            description="Chod de tujhe se na ho paye",
            author="Meetesh Saini",
            points=300,
            image_name="key:latest",
            image_config={"PortBindings": {"22/tcp": [{}]}},
            mi=200,
            ma=400,
        )
        await PreEventProblem.create(
            name="Static_test",
            description="Chod de tujhe se na ho paye",
            author="Meetesh Saini",
            points=20,
            flag="asd",
            url="lugvitc.org",
            date=date.today(),
        )
        await PreEventProblem.create(
            name="New Static Test",
            description="AJJSBFISHDBFHSD",
            author="Meetesh Saini",
            points=21,
            flag="asdf",
            url="lugvitc.org",
            date=date.today(),
        )
        await PreEventProblem.create(
            name="Static_test2",
            description="Chod de tujhe se na ho payga",
            author="Meetesh_Saini",
            points=23,
            flag="asd",
            url="http://lugvitc.org",
            date=date.today(),
        )
        await Problem.create(
            name="In-Plain-Sight",
            description="A curious image with hidden secrets?",
            author="KreativeThinker",
            points=300,
            image_name="key:latest",
            image_config={"PortBindings": {"22/tcp": [{}]}},
            mi=200,
            ma=400,
        )
        await Problem.create(
            name="GitGood",
            description="How to master the art of solving CTFs? Git good nub.",
            author="Aadivishnu and Shoubhit",
            points=300,
            image_name="reg.lugvitc.net/key:latest",
            image_config={"PortBindings": {"22/tcp": [{}]}},
        )
        await Team.create(name="CID Squad", secret_hash=bcrypt.hash("veryverysecret"))
        await Team.create(
            name="Triple A battery", secret_hash=bcrypt.hash("chotiwali"), coins=20
        )
        await PreEventUser.create(tag="23BCE1000", email="dd@ff.in")
        await PreEventUser.create(tag="23BRS1000", email="d2d@ff.in")
        await PreEventSolvedProblem.create(user_id="23BCE1000", problem_id="1")
        await PreEventSolvedProblem.create(user_id="23BRS1000", problem_id="1")
        # await PreEventSolvedProblem.create(
        #     tag="23BAI1000",
        #     problem_id="2"
        # )
        await User.create(
            tag="23BRS1000",
            name="abc",
            team_id=2,
            phone_num=1111111111,
            email="email1@xyz.org",
        )
        await User.create(
            tag="23BCE1000",
            name="def",
            team_id=2,
            phone_num=2222222222,
            email="email1@xyz.org",
        )
        await User.create(
            tag="23BAI1000",
            name="ghi",
            team_id=2,
            phone_num=3333333333,
            email="email1@xyz.org",
        )
        await User.create(
            tag="23BRS2000",
            name="ABC",
            team_id=1,
            phone_num=4444444444,
            email="email1@xyz.org",
        )
        await User.create(
            tag="23BCE2000",
            name="DEF",
            team_id=1,
            phone_num=5555555555,
            email="email1@xyz.org",
        )
        await User.create(
            tag="23BAI2000",
            name="GHI",
            team_id=1,
            phone_num=6666666666,
            email="email1@xyz.org",
        )
        await Hint.create(order=0, problem_id=1, text="This is the first hint")
        await Hint.create(order=1, problem_id=1, text="This is the second hint")
        await Hint.create(order=2, problem_id=1, text="This is the third hint")
        await Hint.create(order=0, problem_id=2, text="This is the first hint")
        await Hint.create(order=1, problem_id=2, text="This is the second hint")
        await SolvedProblem.create(team_id=2, problem_id=1)
        await SolvedProblem.create(team_id=2, problem_id=2)
        await SolvedProblem.create(team_id=1, problem_id=2)
        return {"status": "success", "message": "db init success fr"}
    except Exception as e:
        return {"status": "error", "message": f"bad∂ auth {str(e)}"}

